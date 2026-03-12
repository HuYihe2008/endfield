"""
TCP 登录流程（对齐 Client.old 版本）

关键点：
- 使用 Hg 协议包格式：HeadLen(1) + BodyLen(2, 小端) + CSHead + CsLogin
- 登录消息 msgId=13
- CsLogin 字段布局与 Client.old 一致
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa

from tcp.srsa_bridge import SRSABridge, SRSA_MAGIC

logger = logging.getLogger(__name__)

ERROR_CODES = {
    -1: "ErrUnknown",
    0: "ErrSuccess",
    32: "ErrCommonServerVersionTooLow",
    33: "ErrCommonClientVersionNotEqual",
    34: "ErrCommonClientResVersionNotEqual",
    37: "ErrLoginMultipleSession",
    40: "ErrLoginTokenInvalid",
    41: "ErrLoginMsgFormatInvalid",
    42: "ErrLoginProcessLogin",
    43: "ErrLoginSendMsg",
    44: "ErrCommonPlatformInvalid",
    52: "ErrLoginQueueTimeout",
    53: "ErrLoginQueueFull",
    54: "ErrLoginButTransferringGs",
    62: "ErrLoginLocUnmatch",
    65: "ErrLoginReconnctIncrFailed",
    76: "ErrResourceDataVersionCheckFailed",
    77: "ErrBranchVersionCheckFailed",
    78: "ErrChannelIdCheckFailed",
}


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint value must be >= 0")
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def encode_tag(field_number: int, wire_type: int) -> bytes:
    return encode_varint((field_number << 3) | wire_type)


def encode_string(field_number: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return encode_tag(field_number, 2) + encode_varint(len(raw)) + raw


def encode_bytes(field_number: int, value: bytes) -> bytes:
    return encode_tag(field_number, 2) + encode_varint(len(value)) + value


def encode_bool(field_number: int, value: bool) -> bytes:
    return encode_tag(field_number, 0) + encode_varint(1 if value else 0)


def encode_uint32(field_number: int, value: int) -> bytes:
    return encode_tag(field_number, 0) + encode_varint(value & 0xFFFFFFFF)


def encode_uint64(field_number: int, value: int) -> bytes:
    return encode_tag(field_number, 0) + encode_varint(value & 0xFFFFFFFFFFFFFFFF)


def encode_int64(field_number: int, value: int) -> bytes:
    if value < 0:
        value += 1 << 64
    return encode_tag(field_number, 0) + encode_varint(value)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    shift = 0
    i = offset
    while i < len(data):
        b = data[i]
        i += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return value, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    raise ValueError("incomplete varint")


def iter_fields(data: bytes) -> Iterator[tuple[int, int, bytes | int]]:
    i = 0
    while i < len(data):
        tag, i = decode_varint(data, i)
        field_no = tag >> 3
        wire = tag & 0x7
        if wire == 0:
            value, i = decode_varint(data, i)
            yield field_no, wire, value
        elif wire == 2:
            n, i = decode_varint(data, i)
            end = i + n
            if end > len(data):
                raise ValueError("field length overflow")
            yield field_no, wire, data[i:end]
            i = end
        elif wire == 5:
            end = i + 4
            if end > len(data):
                raise ValueError("fixed32 overflow")
            yield field_no, wire, data[i:end]
            i = end
        elif wire == 1:
            end = i + 8
            if end > len(data):
                raise ValueError("fixed64 overflow")
            yield field_no, wire, data[i:end]
            i = end
        else:
            raise ValueError(f"unsupported wire type: {wire}")


def _to_int(value: Any, default: int) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _extract_version_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in (
            "version",
            "resVersion",
            "res_version",
            "client_res_version",
            "resourceVersion",
            "resource_version",
            "onlineVersion",
            "request_version",
        ):
            raw = value.get(key)
            if raw:
                return str(raw)
        pkg = value.get("pkg")
        if isinstance(pkg, dict):
            for key in ("version", "resVersion", "res_version", "client_res_version"):
                raw = pkg.get(key)
                if raw:
                    return str(raw)
    return str(value) if value != "" else ""


def _resolve_launcher_version(ctx: dict[str, Any]) -> str:
    for candidate in (
        ctx.get("a6"),
        ctx.get("client_version"),
        ctx.get("launcher_version"),
        ctx.get("config", {}).get("launcher_version"),
    ):
        resolved = _extract_version_string(candidate)
        if resolved:
            return resolved
    return "1.0.14"


def _resolve_online_res_version(ctx: dict[str, Any]) -> str:
    for candidate in (
        ctx.get("a7"),
        ctx.get("res_version"),
        ctx.get("config", {}).get("res_version"),
    ):
        resolved = _extract_version_string(candidate)
        if resolved:
            return resolved
    return _resolve_launcher_version(ctx)


def _resolve_branch_tag(ctx: dict[str, Any], launcher_version: str) -> str:
    _ = launcher_version
    return str(ctx.get("branch_tag") or ctx.get("a14") or "prod-obt-official")


def _resolve_login_a1_a2(ctx: dict[str, Any]) -> tuple[str, str]:
    if "a1" in ctx or "a2" in ctx:
        return str(ctx.get("a1") or ""), str(ctx.get("a2") or "")

    uid = str(ctx.get("uid") or "")
    token = str(ctx.get("token") or ctx.get("grant_code") or "")
    return uid, token


def _resolve_channel_id(ctx: dict[str, Any]) -> int:
    if "a21" in ctx:
        return _to_int(ctx.get("a21"), default=1)
    if "channel_master_id" in ctx:
        return _to_int(ctx.get("channel_master_id"), default=1)
    return _to_int(
        (ctx.get("u8_token_by_channel_token") or {}).get("channelMasterId"),
        default=1,
    )


def _resolve_sub_channel(ctx: dict[str, Any]) -> int:
    if "a22" in ctx:
        return _to_int(ctx.get("a22"), default=1)
    if "sub_channel" in ctx:
        return _to_int(ctx.get("sub_channel"), default=1)
    return _to_int(
        (
            ctx.get("config", {})
            .get("launcher_version", {})
            .get("pkg", {})
            .get("sub_channel")
        ),
        default=1,
    )


def _ipv4_to_int(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default

    if isinstance(value, int):
        return value

    raw = str(value).strip()
    if not raw:
        return default

    if "." not in raw:
        return _to_int(raw, default)

    parts = raw.split(".")
    if len(parts) != 4:
        return default

    out = 0
    for part in parts:
        octet = _to_int(part, -1)
        if octet < 0 or octet > 255:
            return default
        out = (out << 8) | octet
    return out


def _resolve_device_info_fields(ctx: dict[str, Any], online_res_version: str) -> dict[str, Any]:
    device_id = str(
        ctx.get("device_id")
        or ctx.get("passport_device_token")
        or ctx.get("device_token")
        or ""
    )
    if not device_id:
        seed = str(ctx.get("uid") or ctx.get("a1") or "unknown")
        device_id = f"pc-{seed}"

    return {
        "device_id": device_id,
        "os": str(ctx.get("device_os") or ctx.get("os") or "Windows"),
        "os_ver": str(ctx.get("device_os_ver") or ctx.get("os_ver") or "10.0"),
        "brand": str(ctx.get("device_brand") or ctx.get("brand") or "PC"),
        "model": str(ctx.get("device_model") or ctx.get("model") or "Windows"),
        "simulator": str(ctx.get("device_simulator") or ctx.get("simulator") or "0"),
        "network": str(ctx.get("device_network") or ctx.get("network") or "WIFI"),
        "carrier": str(ctx.get("device_carrier") or ctx.get("carrier") or ""),
        "language": str(ctx.get("device_language") or ctx.get("language") or "zh-CN"),
        "country_iso_code": str(ctx.get("device_country") or ctx.get("country_iso_code") or "CN"),
        "ipv4": _ipv4_to_int(ctx.get("device_ipv4"), 0),
        "client_res_version": str(ctx.get("device_client_res_version") or online_res_version or ""),
    }


def _build_device_info_payload(fields: dict[str, Any]) -> bytes:
    payload = b""
    if fields["device_id"]:
        payload += encode_string(1, fields["device_id"])
    if fields["os"]:
        payload += encode_string(2, fields["os"])
    if fields["os_ver"]:
        payload += encode_string(3, fields["os_ver"])
    if fields["brand"]:
        payload += encode_string(4, fields["brand"])
    if fields["model"]:
        payload += encode_string(5, fields["model"])
    if fields["simulator"]:
        payload += encode_string(6, fields["simulator"])
    if fields["network"]:
        payload += encode_string(7, fields["network"])
    if fields["carrier"]:
        payload += encode_string(8, fields["carrier"])
    if fields["language"]:
        payload += encode_string(9, fields["language"])
    if fields["country_iso_code"]:
        payload += encode_string(10, fields["country_iso_code"])
    if fields["ipv4"]:
        payload += encode_int64(11, int(fields["ipv4"]))
    if fields["client_res_version"]:
        payload += encode_string(12, fields["client_res_version"])
    return payload


def generate_rsa_keypair() -> tuple[str, str]:
    """生成登录使用的 RSA 密钥对（PEM 字符串）"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return public_pem, private_pem


def _resolve_client_public_key_bytes(ctx: dict[str, Any]) -> tuple[bytes, str]:
    if _to_bool(ctx.get("minimal_login_fields", False)):
        return b"", "minimal_disabled"

    fmt = str(ctx.get("client_public_key_format") or "der").strip().lower()

    raw = ctx.get("client_public_key_bytes")
    if isinstance(raw, (bytes, bytearray)) and raw:
        key_bytes = bytes(raw)
    else:
        key_str = str(ctx.get("client_public_key") or "")
        key_bytes = key_str.encode("utf-8") if key_str else b""

    raw_der = ctx.get("client_public_key_der_bytes")
    der_bytes = bytes(raw_der) if isinstance(raw_der, (bytes, bytearray)) and raw_der else b""

    if not key_bytes:
        if der_bytes:
            return der_bytes, "der"
        return b"", "none"

    looks_like_pem = key_bytes.lstrip().startswith(b"-----BEGIN")
    if fmt == "pem":
        return key_bytes, "pem"
    if fmt == "der":
        if der_bytes:
            return der_bytes, "der"
        if not looks_like_pem:
            return key_bytes, "raw"
        try:
            pub = load_pem_public_key(key_bytes)
            der = pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return der, "der"
        except Exception:
            return key_bytes, "pem_raw"

    if der_bytes:
        return der_bytes, "der"

    if looks_like_pem:
        try:
            pub = load_pem_public_key(key_bytes)
            der = pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return der, "der"
        except Exception:
            return key_bytes, "pem_raw"

    return key_bytes, "raw"


def build_cs_login_body(ctx: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    """
    构建 CsLogin 消息体

    对齐 Il2CppInspector 导出的 MSG_A1 / CsLogin:
        1: string a14
        2: string a7
        3: string a6
        4: string a13
        5: string a1
        6: string a2
        7: bytes  a8
        8: enum   a9
        9: enum   a10
        10: int32 a12
        11: uint64 a5
        12: enum  a11
        13: int32 a21
        14: int32 a22
        15: int32 a4
        16: int32 client_language
        17: DEVICE_INFO a23
    """
    launcher_version = str(ctx.get("a6") or _resolve_launcher_version(ctx))
    online_res_version = str(ctx.get("a7") or _resolve_online_res_version(ctx))
    branch_tag = str(ctx.get("a14") or _resolve_branch_tag(ctx, launcher_version))
    a13_value = str(ctx.get("a13") or "")

    a1_value, a2_value = _resolve_login_a1_a2(ctx)
    public_key_bytes, public_key_format = _resolve_client_public_key_bytes(ctx)

    if "a9" in ctx:
        a9_pay_platform = _to_int(ctx.get("a9"), 3)
    else:
        a9_pay_platform = _to_int(ctx.get("platform_id"), 3)

    if "a10" in ctx:
        a10_area = _to_int(ctx.get("a10"), 0)
    else:
        a10_area = _to_int(ctx.get("area"), 0)

    if "a11" in ctx:
        a11_env = _to_int(ctx.get("a11"), 2)
    else:
        a11_env = _to_int(ctx.get("env"), 2)

    a12_value = _to_int(ctx.get("a12"), _to_int(ctx.get("pay_platform"), 2))
    a5_value = _to_int(ctx.get("a5"), 0)
    a4_value = _to_int(ctx.get("a4"), 0)
    client_language = _to_int(ctx.get("client_language"), 0)
    channel_id = _resolve_channel_id(ctx)
    sub_channel = _resolve_sub_channel(ctx)
    force_emit_a10 = _to_bool(ctx.get("force_emit_a10"))
    force_emit_a12 = _to_bool(ctx.get("force_emit_a12"))
    force_emit_a5 = _to_bool(ctx.get("force_emit_a5"))
    disable_device_info = _to_bool(ctx.get("disable_device_info"))
    disable_client_public_key = _to_bool(ctx.get("disable_client_public_key"))

    if disable_client_public_key:
        public_key_bytes = b""
        public_key_format = "disabled"

    device_fields = _resolve_device_info_fields(ctx, online_res_version)
    device_payload = b"" if disable_device_info else _build_device_info_payload(device_fields)

    field_trace: list[dict[str, Any]] = []

    def _append_field(field_no: int, label: str, value: bytes, *, wire_type: int, detail: dict[str, Any]) -> None:
        nonlocal msg
        msg += value
        item = {
            "field_no": field_no,
            "label": label,
            "wire_type": wire_type,
            "encoded_len": len(value),
        }
        item.update(detail)
        field_trace.append(item)

    msg = b""

    if branch_tag:
        encoded = encode_string(1, branch_tag)
        _append_field(1, "a14", encoded, wire_type=2, detail={"value": branch_tag, "value_len": len(branch_tag.encode("utf-8"))})

    if online_res_version:
        encoded = encode_string(2, online_res_version)
        _append_field(2, "a7", encoded, wire_type=2, detail={"value": online_res_version, "value_len": len(online_res_version.encode("utf-8"))})

    if launcher_version:
        encoded = encode_string(3, launcher_version)
        _append_field(3, "a6", encoded, wire_type=2, detail={"value": launcher_version, "value_len": len(launcher_version.encode("utf-8"))})

    if a13_value:
        encoded = encode_string(4, a13_value)
        _append_field(4, "a13", encoded, wire_type=2, detail={"value": a13_value, "value_len": len(a13_value.encode("utf-8"))})

    if a1_value:
        encoded = encode_string(5, a1_value)
        _append_field(5, "a1", encoded, wire_type=2, detail={"value": a1_value, "value_len": len(a1_value.encode("utf-8"))})

    if a2_value:
        encoded = encode_string(6, a2_value)
        _append_field(
            6,
            "a2",
            encoded,
            wire_type=2,
            detail={
                "value_len": len(a2_value.encode("utf-8")),
                "value_sha256": hashlib.sha256(a2_value.encode("utf-8")).hexdigest(),
            },
        )

    if public_key_bytes:
        encoded = encode_bytes(7, public_key_bytes)
        _append_field(
            7,
            "a8",
            encoded,
            wire_type=2,
            detail={
                "value_len": len(public_key_bytes),
                "value_sha256": hashlib.sha256(public_key_bytes).hexdigest(),
                "value_format": public_key_format,
            },
        )

    if a9_pay_platform != 0:
        encoded = encode_uint32(8, a9_pay_platform)
        _append_field(8, "a9", encoded, wire_type=0, detail={"value": a9_pay_platform})

    if force_emit_a10 or a10_area != 0:
        encoded = encode_uint32(9, a10_area)
        _append_field(9, "a10", encoded, wire_type=0, detail={"value": a10_area})

    if force_emit_a12 or a12_value != 0:
        encoded = encode_uint32(10, a12_value)
        _append_field(10, "a12", encoded, wire_type=0, detail={"value": a12_value})

    if force_emit_a5 or a5_value != 0:
        encoded = encode_uint64(11, a5_value)
        _append_field(11, "a5", encoded, wire_type=0, detail={"value": a5_value})

    if a11_env != 0:
        encoded = encode_uint32(12, a11_env)
        _append_field(12, "a11", encoded, wire_type=0, detail={"value": a11_env})

    encoded = encode_uint32(13, channel_id)
    _append_field(13, "a21", encoded, wire_type=0, detail={"value": channel_id})

    encoded = encode_uint32(14, sub_channel)
    _append_field(14, "a22", encoded, wire_type=0, detail={"value": sub_channel})

    if a4_value != 0:
        encoded = encode_uint32(15, a4_value)
        _append_field(15, "a4", encoded, wire_type=0, detail={"value": a4_value})

    encoded = encode_uint32(16, client_language)
    _append_field(16, "client_language", encoded, wire_type=0, detail={"value": client_language})

    if device_payload:
        encoded = encode_bytes(17, device_payload)
        _append_field(
            17,
            "a23",
            encoded,
            wire_type=2,
            detail={
                "value_len": len(device_payload),
                "device_id": device_fields.get("device_id", ""),
                "device_os": device_fields.get("os", ""),
            },
        )

    meta = {
        "a14": branch_tag,
        "a7": online_res_version,
        "a6": launcher_version,
        "a13": a13_value,
        "a1": a1_value,
        "token_len": len(a2_value),
        "a9": a9_pay_platform,
        "a10": a10_area,
        "a12": a12_value,
        "a5": a5_value,
        "a11": a11_env,
        "a21": channel_id,
        "a22": sub_channel,
        "a4": a4_value,
        "client_language": client_language,
        "client_public_key_len": len(public_key_bytes),
        "client_public_key_format": public_key_format,
        "device_info_len": len(device_payload),
        "field_trace": field_trace,
        "field_order": [item["field_no"] for item in field_trace],
        "body_len": len(msg),
        "body_sha256": hashlib.sha256(msg).hexdigest(),
    }

    logger.info("[TCP] CsLogin 字段详情:")
    for item in field_trace:
        if item["field_no"] in {6, 7}:
            logger.info(f"  Field {item['field_no']} ({item['label']}): encoded_len={item['encoded_len']}, value_len={item.get('value_len', 'N/A')}, sha256={item.get('value_sha256', 'N/A')[:16]}...")
        else:
            logger.info(f"  Field {item['field_no']} ({item['label']}): encoded_len={item['encoded_len']}")

    logger.info(
        f"[TCP] build_cs_login_body 输出长度：{len(msg)} "
        f"(token 原始长度：{len(a2_value)}, client_public_key 长度：{len(public_key_bytes)}, device_info 长度：{len(device_payload)})"
    )

    return msg, meta


def build_cs_head(msgid: int, up_seqid: int, down_seqid: int = 0) -> bytes:
    return _build_cs_head(
        msgid=msgid,
        up_seqid=up_seqid,
        down_seqid=down_seqid,
    )


def _build_cs_head(
    msgid: int,
    up_seqid: int,
    down_seqid: int = 0,
    total_pack_count: int = 1,
    current_pack_index: int = 0,
    is_compress: bool = False,
    checksum: Optional[int] = None,
    force_emit_down_seqid: bool = False,
    force_emit_checksum: bool = False,
    is_login: bool = False,
) -> bytes:
    """
    构建 CS 头协议

    参数:
        is_login: 是否为登录包。登录包只包含 msgid 和 checksum，不包含 seqid 等字段
    """
    msg = b""
    msg += encode_uint32(1, msgid)

    # 登录包只包含 field 1 (msgid) 和 field 7 (checksum)
    # 不包含 field 2 (up_seqid) 和 field 4 (total_pack_count)
    if not is_login:
        msg += encode_uint64(2, up_seqid)
        if force_emit_down_seqid or down_seqid != 0:
            msg += encode_uint64(3, down_seqid)
        msg += encode_uint32(4, total_pack_count)
        if current_pack_index != 0:
            msg += encode_uint32(5, current_pack_index)
        if is_compress:
            msg += encode_bool(6, is_compress)

    if force_emit_checksum or checksum is not None:
        msg += encode_uint32(7, _to_int(checksum, 0))
    return msg


def build_tcp_packet(
    msgid: int,
    body: bytes,
    seq_id: int,
    down_seqid: int = 0,
    total_pack_count: int = 1,
    current_pack_index: int = 0,
    is_compress: bool = False,
    checksum: Optional[int] = None,
    force_emit_down_seqid: bool = False,
    force_emit_checksum: bool = False,
    body_len_override: Optional[int] = None,
    is_login: bool = False,
) -> bytes:
    if len(body) == 0 and body_len_override is not None and (force_emit_checksum or checksum is not None):
        return build_login_head_packet(
            msgid,
            body_len_override,
            checksum=checksum,
            force_emit_checksum=force_emit_checksum,
        )

    cs_head = _build_cs_head(
        msgid=msgid,
        up_seqid=seq_id,
        down_seqid=down_seqid,
        total_pack_count=total_pack_count,
        current_pack_index=current_pack_index,
        is_compress=is_compress,
        checksum=checksum,
        force_emit_down_seqid=force_emit_down_seqid,
        force_emit_checksum=force_emit_checksum,
        is_login=is_login,
    )
    head_len = len(cs_head)
    body_len = body_len_override if body_len_override is not None else len(body)

    packet = bytearray()
    packet.append(head_len)
    packet.extend(struct.pack("<H", body_len))
    packet.extend(cs_head)
    packet.extend(body)
    return bytes(packet)


def build_login_head_packet(
    msgid: int,
    body_len: int,
    checksum: Optional[int] = None,
    *,
    force_emit_checksum: bool = False,
) -> bytes:
    cs_head = encode_uint32(1, msgid)
    if force_emit_checksum or checksum is not None:
        cs_head += encode_uint32(7, _to_int(checksum, 0))

    packet = bytearray()
    packet.append(len(cs_head))
    packet.extend(struct.pack("<H", body_len))
    packet.extend(cs_head)
    return bytes(packet)


def _is_srsa_encrypted(data: bytes) -> bool:
    return len(data) >= 12 and data[:4] == SRSA_MAGIC


def _parse_sc_login(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        for field_no, wire, value in iter_fields(data):
            if wire == 2 and isinstance(value, bytes):
                if field_no == 1:
                    out["uid"] = value.decode("utf-8", errors="replace")
                elif field_no == 2:
                    out["login_token"] = value.decode("utf-8", errors="replace")
                elif field_no == 3:
                    out["server_public_key"] = value.hex()
                elif field_no == 4:
                    out["server_encryp_nonce"] = value.hex()
            elif wire == 0 and isinstance(value, int):
                if field_no == 5:
                    out["is_client_reconnect"] = bool(value)
                elif field_no == 6:
                    out["is_first_login"] = bool(value)
                elif field_no == 7:
                    out["is_reconnect"] = bool(value)
                elif field_no == 8:
                    out["server_time"] = value
    except Exception as exc:
        out["parse_error"] = str(exc)
    return out


def _parse_error_response(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        for field_no, wire, value in iter_fields(data):
            if wire == 0 and isinstance(value, int) and field_no == 1:
                out["error_code"] = value
            elif wire == 2 and isinstance(value, bytes) and field_no == 2:
                out["details"] = value.decode("utf-8", errors="replace")
    except Exception:
        pass
    return out


@dataclass
class LoginResponse:
    uid: str = ""
    login_token: str = ""
    server_public_key: str = ""
    server_encryp_nonce: str = ""
    server_time: int = 0
    is_first_login: bool = False
    is_reconnect: bool = False


class TCPClient:
    """TCP 客户端（对齐 Client.old 登录流程）"""

    def __init__(
        self,
        dll_dir: Path,
        timeout: float = 30.0,
    ):
        self.dll_dir = dll_dir
        self.timeout = timeout
        self.srsa_bridge: Optional[SRSABridge] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._seq_id = 1
        self.login_parsed: dict[str, Any] = {}

    async def connect(self, host: str, port: int) -> bool:
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )
            logger.info(f"[TCP] 连接成功：{host}:{port}")
            return True
        except Exception as e:
            logger.error(f"[TCP] 连接失败：{e}")
            return False

    def disconnect(self) -> None:
        if self.writer:
            self.writer.close()
        logger.info("[TCP] 已断开连接")

    async def _read_exact(self, n: int) -> bytes:
        if not self.reader:
            raise RuntimeError("未连接")
        return await self.reader.readexactly(n)

    async def _write(self, data: bytes) -> None:
        if not self.writer:
            raise RuntimeError("未连接")
        self.writer.write(data)
        await self.writer.drain()

    def init_srsa(self) -> None:
        """初始化 SRSA 加密桥接"""
        logger.info("[SRSA] 初始化 SRSA 加密桥接...")
        self.srsa_bridge = SRSABridge(self.dll_dir)
        logger.info(f"[SRSA] SRSA 版本：{self.srsa_bridge.version}")

    async def login(
        self,
        uid: str,
        grant_code: str,
        client_version: str = "1.0.14",
        platform_id: int = 3,
        area: int = 0,
        env: int = 2,
        login_ctx: Optional[dict[str, Any]] = None,
    ) -> LoginResponse:
        """执行 TCP 登录流程"""
        logger.info(f"[TCP] 登录参数：uid={uid}, grant_code={grant_code[:50]}... (总长度：{len(grant_code)})")

        ctx: dict[str, Any] = {
            "uid": uid,
            "token": grant_code,
            "grant_code": grant_code,
            "client_version": client_version,
            "launcher_version": client_version,
            "platform_id": platform_id,
            "area": area,
            "env": env,
            "force_emit_a10": True,
            "minimal_login_fields": False,
            "disable_device_info": False,
        }
        if login_ctx:
            ctx.update(login_ctx)

        if not self.srsa_bridge:
            self.init_srsa()

        public_key, _private_key = generate_rsa_keypair()
        ctx["client_public_key"] = public_key
        ctx["client_public_key_bytes"] = public_key.encode("utf-8")
        ctx["client_public_key_format"] = "pem"
        logger.info(f"[TCP] RSA 密钥对生成：PEM 长度={len(public_key)}")

        cs_body_plain, body_meta = build_cs_login_body(ctx)

        # 输出构建信息用于调试
        logger.info(f"[TCP] build_cs_login_body 输出长度：{len(cs_body_plain)}")
        logger.info(f"[TCP] 字段顺序：{body_meta['field_order']}")

        cs_body = cs_body_plain

        # 输出明文前 32 字节用于调试
        logger.info(f"[TCP] CsLogin 明文前 32 字节：{cs_body_plain[:32].hex()}")
        logger.info(f"[TCP] CsLogin 明文长度：{len(cs_body_plain)}")

        if self.srsa_bridge is not None:
            try:
                cs_body = self.srsa_bridge.encrypt_login_body(cs_body_plain)
                logger.info(f"[TCP] SRSA 加密后前 16 字节：{cs_body[:16].hex()}")
                logger.info(f"[TCP] 是否包含 SRSA 头：{cs_body[:4] == SRSA_MAGIC}")
            except Exception as exc:
                logger.error(f"[TCP] SRSA 加密失败：{exc}")
                raise

        msgid = 13
        seq_id = self._seq_id
        self._seq_id += 1

        checksum = zlib.crc32(cs_body_plain) & 0xFFFFFFFF
        logger.info(f"[TCP] 使用 checksum: {checksum} (0x{checksum:08x})")

        cs_head = encode_uint32(1, msgid)  # field 1: msgid
        cs_head += encode_uint32(7, checksum)  # field 7: checksum
        head_len = len(cs_head)
        body_len = len(cs_body)

        # 根据抓包，登录流程使用两个独立的 TCP 包：
        # 包 1: TCP 头部 (3 字节) + CSHead (8 字节) = 11 字节
        # 包 2: SRSA 加密数据 (1312 字节)
        
        # 构建第一个包：TCP 头部 + CSHead
        head_packet = bytearray()
        head_packet.append(head_len)
        head_packet.extend(struct.pack("<H", body_len))
        head_packet.extend(cs_head)
        
        # 第二个包：SRSA 加密 body（单独的包）
        body_packet = cs_body

        logger.info(f"[TCP] 双包发送：头包={len(head_packet)}字节，body 包={len(body_packet)}字节")
        logger.info(f"[TCP] CSHead hex: {cs_head.hex()}")

        # 发送第一个包（头包）
        self.writer.write(head_packet)
        await self.writer.drain()
        logger.info("[TCP] 头包已发送")
        
        # 发送第二个包（body 包）
        self.writer.write(body_packet)
        await self.writer.drain()
        logger.info("[TCP] body 包已发送")

        header = await self._read_exact(3)
        head_len = header[0]
        body_len = struct.unpack("<H", header[1:3])[0]
        remaining = await self._read_exact(head_len + body_len)
        resp = header + remaining

        parsed: dict[str, Any] = {
            "resp_len": len(resp),
            "resp_head_len": head_len,
            "resp_body_len": body_len,
        }

        if len(resp) >= 3 + head_len + body_len:
            resp_body = resp[3 + head_len:3 + head_len + body_len]

            if _is_srsa_encrypted(resp_body) and self.srsa_bridge is not None:
                parsed["response_encrypted"] = True
                try:
                    resp_body = self.srsa_bridge.decrypt_login_body(resp_body)
                    parsed["decrypted_len"] = len(resp_body)
                except Exception as e:
                    parsed["decrypt_error"] = str(e)

            error_info = _parse_error_response(resp_body)
            if error_info.get("error_code") is not None:
                err_code = int(error_info["error_code"])
                parsed["error_code"] = err_code
                parsed["error_name"] = ERROR_CODES.get(err_code, f"Unknown({err_code})")
                parsed["error_details"] = error_info.get("details", "")
                logger.error(f"[TCP] 登录失败：{parsed['error_name']}({err_code}), details={parsed['error_details']}")
                raise RuntimeError(f"登录失败：{parsed['error_name']}({err_code})")
            else:
                sc_login = _parse_sc_login(resp_body)
                if sc_login:
                    parsed["sc_login"] = sc_login
                    logger.info(f"[TCP] 登录成功：uid={sc_login.get('uid')}")
                    return LoginResponse(
                        uid=sc_login.get("uid", ""),
                        login_token=sc_login.get("login_token", ""),
                        server_public_key=sc_login.get("server_public_key", ""),
                        server_encryp_nonce=sc_login.get("server_encryp_nonce", ""),
                        server_time=sc_login.get("server_time", 0),
                        is_first_login=sc_login.get("is_first_login", False),
                        is_reconnect=sc_login.get("is_reconnect", False),
                    )

        self.login_parsed = parsed
        raise RuntimeError("未识别的登录响应")
