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
    40: "ErrLoginTokenInvalid",
    41: "ErrLoginMsgFormatInvalid",
    42: "ErrLoginProcessLogin",
    44: "ErrCommonPlatformInvalid",
    78: "ErrChecksumInvalid",
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


def _resolve_launcher_version(ctx: dict[str, Any]) -> str:
    return str(ctx.get("a6") or ctx.get("client_version") or ctx.get("launcher_version") or "1.0.14")


def _resolve_online_res_version(ctx: dict[str, Any]) -> str:
    return str(ctx.get("a7") or ctx.get("res_version") or _resolve_launcher_version(ctx))


def _resolve_branch_tag(ctx: dict[str, Any], launcher_version: str) -> str:
    _ = launcher_version
    return str(ctx.get("branch_tag") or ctx.get("a14") or "prod-obt-official")


def _resolve_login_a1_a2(ctx: dict[str, Any]) -> tuple[str, str]:
    if "a1" in ctx or "a2" in ctx:
        return str(ctx.get("a1") or ""), str(ctx.get("a2") or "")

    uid = str(ctx.get("uid") or "")
    token = str(ctx.get("token") or ctx.get("grant_code") or "")
    return uid, token


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
    
    根据 proto 定义，CsLogin 只包含以下字段：
    message CsLogin {
        string channel = 1;
        string client_res_version = 2;
        string client_version = 3;
        string uid = 5;
        string token = 6;
        string client_public_key = 7;
        ClientPlatformType platform_id = 8;
        AreaType area = 9;
        EnvType env = 12;
        int32 client_language = 16;
    }
    """
    launcher_version = _resolve_launcher_version(ctx)
    online_res_version = _resolve_online_res_version(ctx)
    
    # Field 1: channel (不是 branch_tag!)
    channel = str(ctx.get("channel") or "")
    
    a1_value, a2_value = _resolve_login_a1_a2(ctx)
    uid = str(ctx.get("uid") or a1_value or "")
    token = str(ctx.get("token") or ctx.get("grant_code") or a2_value or "")
    
    platform_id = _to_int(ctx.get("platform_id") or ctx.get("a9"), 3)
    area = _to_int(ctx.get("area") or ctx.get("a10"), 0)
    env = _to_int(ctx.get("env") or ctx.get("a11"), 2)
    client_language = _to_int(ctx.get("client_language"), 0)
    
    disable_client_public_key = _to_bool(ctx.get("disable_client_public_key"))
    
    # client_public_key 是 string 类型
    # 尝试使用 Base64 格式（不含 PEM 头尾和换行）
    client_public_key_str = str(ctx.get("client_public_key_b64") or ctx.get("client_public_key") or "")
    if disable_client_public_key:
        client_public_key_str = ""

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

    # Field 1: channel (始终发送，即使是空字符串)
    # 服务器可能期望 field 1 始终存在
    encoded = encode_string(1, channel)
    _append_field(1, "channel", encoded, wire_type=2, detail={"value": channel, "value_len": len(channel.encode("utf-8"))})

    # Field 2: client_res_version (仅在非空时发送)
    if online_res_version:
        encoded = encode_string(2, online_res_version)
        _append_field(2, "client_res_version", encoded, wire_type=2, detail={"value": online_res_version, "value_len": len(online_res_version.encode("utf-8"))})

    # Field 3: client_version (仅在非空时发送)
    if launcher_version:
        encoded = encode_string(3, launcher_version)
        _append_field(3, "client_version", encoded, wire_type=2, detail={"value": launcher_version, "value_len": len(launcher_version.encode("utf-8"))})

    # Field 5: uid (仅在非空时发送)
    if uid:
        encoded = encode_string(5, uid)
        _append_field(5, "uid", encoded, wire_type=2, detail={"value": uid, "value_len": len(uid.encode("utf-8"))})

    # Field 6: token (仅在非空时发送)
    if token:
        encoded = encode_string(6, token)
        _append_field(6, "token", encoded, wire_type=2, detail={"value_len": len(token.encode("utf-8")), "value_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest()})

    # Field 7: client_public_key (仅在非空时发送)
    # 注意：这是 string 类型，应该发送 PEM 格式的公钥字符串
    if client_public_key_str:
        encoded = encode_string(7, client_public_key_str)
        _append_field(
            7,
            "client_public_key",
            encoded,
            wire_type=2,
            detail={
                "value_len": len(client_public_key_str),
                "value_sha256": hashlib.sha256(client_public_key_str.encode("utf-8")).hexdigest(),
            },
        )

    # Field 8: platform_id (仅在非零时发送)
    if platform_id != 0:
        encoded = encode_uint32(8, platform_id)
        _append_field(8, "platform_id", encoded, wire_type=0, detail={"value": platform_id})

    # Field 9: area (始终发送，即使是 0)
    # 服务器可能期望 field 9 始终存在
    encoded = encode_uint32(9, area)
    _append_field(9, "area", encoded, wire_type=0, detail={"value": area})

    # Field 12: env (仅在非零时发送)
    if env != 0:
        encoded = encode_uint32(12, env)
        _append_field(12, "env", encoded, wire_type=0, detail={"value": env})

    # Field 16: client_language (始终发送，即使是 0)
    # 服务器可能期望 field 16 始终存在
    encoded = encode_uint32(16, client_language)
    _append_field(16, "client_language", encoded, wire_type=0, detail={"value": client_language})

    meta = {
        "channel": channel,
        "client_res_version": online_res_version,
        "client_version": launcher_version,
        "uid": uid,
        "token_len": len(token),
        "platform_id": platform_id,
        "area": area,
        "env": env,
        "client_language": client_language,
        "client_public_key_len": len(client_public_key_str),
        "field_trace": field_trace,
        "field_order": [item["field_no"] for item in field_trace],
        "body_len": len(msg),
        "body_sha256": hashlib.sha256(msg).hexdigest(),
    }

    # 输出详细字段信息用于调试
    logger.info(f"[TCP] CsLogin 字段详情 (padding 前):")
    for item in field_trace:
        if item["field_no"] == 6:  # token
            logger.info(f"  Field {item['field_no']} ({item['label']}): encoded_len={item['encoded_len']}, value_len={item.get('value_len', 'N/A')}, sha256={item.get('value_sha256', 'N/A')[:16]}...")
        elif item["field_no"] == 7:  # client_public_key
            logger.info(f"  Field {item['field_no']} ({item['label']}): encoded_len={item['encoded_len']}, value_len={item.get('value_len', 'N/A')}")
        else:
            logger.info(f"  Field {item['field_no']} ({item['label']}): encoded_len={item['encoded_len']}")

    logger.info(f"[TCP] build_cs_login_body 输出长度：{len(msg)} (token 原始长度：{len(token)}, client_public_key 长度：{len(client_public_key_str)})")

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

        if not self.srsa_bridge:
            self.init_srsa()

        public_key, private_key = generate_rsa_keypair()
        ctx["client_public_key"] = public_key
        ctx["client_public_key_bytes"] = public_key.encode("utf-8")
        try:
            pub = load_pem_public_key(public_key.encode("utf-8"))
            der_bytes = pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            ctx["client_public_key_der_bytes"] = der_bytes
            # 将 DER 编码转换为 Base64 字符串（不含 PEM 头尾和换行）
            import base64
            b64_str = base64.b64encode(der_bytes).decode('ascii')
            ctx["client_public_key_b64"] = b64_str
            logger.info(f"[TCP] RSA 密钥对生成：PEM 长度={len(public_key)}, DER 长度={len(der_bytes)}, Base64 长度={len(b64_str)}")
        except Exception as e:
            logger.error(f"[TCP] RSA 密钥转换失败：{e}")
            ctx["client_public_key_b64"] = ""
        ctx["client_public_key_format"] = "der"

        cs_body_plain, body_meta = build_cs_login_body(ctx)

        # 输出构建信息用于调试
        logger.info(f"[TCP] build_cs_login_body 输出长度：{len(cs_body_plain)}")
        logger.info(f"[TCP] 字段顺序：{body_meta['field_order']}")

        # SRSA 混合加密触发条件：输入长度 >= 1021 字节
        # 正常客户端明文长度：1053 字节
        # 如果明文不足 1053 字节，在 token 字段末尾添加 padding
        HYBRID_ENCRYPT_THRESHOLD = 1053
        if len(cs_body_plain) < HYBRID_ENCRYPT_THRESHOLD:
            padding_needed = HYBRID_ENCRYPT_THRESHOLD - len(cs_body_plain)
            logger.info(f"[TCP] 需要 padding: {padding_needed} 字节 (当前 {len(cs_body_plain)} -> 目标 {HYBRID_ENCRYPT_THRESHOLD})")

            # 方案：在 token 字段（field 6）末尾添加 padding
            # 使用 protobuf 解析找到 field 6 的准确位置
            idx = -1
            len_start = -1
            current_len = 0
            len_bytes = 0
            
            # 解析 protobuf 找到 field 6
            i = 0
            while i < len(cs_body_plain):
                # 读取 tag
                tag = 0
                shift = 0
                while i < len(cs_body_plain):
                    b = cs_body_plain[i]
                    i += 1
                    tag |= (b & 0x7F) << shift
                    if (b & 0x80) == 0:
                        break
                    shift += 7
                
                field_no = tag >> 3
                wire_type = tag & 0x7
                
                if wire_type == 0:  # Varint
                    # 跳过 varint 值
                    while i < len(cs_body_plain):
                        b = cs_body_plain[i]
                        i += 1
                        if (b & 0x80) == 0:
                            break
                elif wire_type == 1:  # 64-bit
                    i += 8
                elif wire_type == 2:  # Length-delimited
                    # 解析长度
                    length = 0
                    shift = 0
                    len_bytes_count = 0
                    while i < len(cs_body_plain):
                        b = cs_body_plain[i]
                        i += 1
                        len_bytes_count += 1
                        length |= (b & 0x7F) << shift
                        if (b & 0x80) == 0:
                            break
                        shift += 7
                    
                    if field_no == 6:  # 找到 token 字段
                        # tag 的结束位置就是 len_start
                        len_start = i - len_bytes_count
                        # 重新计算 tag 占用的字节数
                        tag_bytes = 0
                        temp_tag = tag
                        while temp_tag > 0x7F:
                            tag_bytes += 1
                            temp_tag >>= 7
                        tag_bytes += 1
                        idx = len_start - tag_bytes
                        current_len = length
                        len_bytes = len_bytes_count
                        break
                    
                    i += length
                elif wire_type == 5:  # 32-bit
                    i += 4
                else:
                    logger.warning(f"[TCP] 遇到未知的 wire type: {wire_type} at position {i}")
                    # 跳过未知类型，尝试继续解析
                    break
            
            if idx != -1:
                # 查找 token 数据结束位置
                data_start = len_start + len_bytes
                data_end = data_start + current_len

                # 添加 padding 到 token 末尾
                cs_body_plain = cs_body_plain[:data_end] + bytes([0x20] * padding_needed) + cs_body_plain[data_end:]

                # 更新 token 字段长度 (使用 varint 编码)
                new_len = current_len + padding_needed

                # 编码新的 varint 长度
                new_len_bytes = bytearray()
                temp_len = new_len
                while temp_len > 0x7F:
                    new_len_bytes.append((temp_len & 0x7F) | 0x80)
                    temp_len >>= 7
                new_len_bytes.append(temp_len)

                # 替换长度字节
                cs_body_plain = cs_body_plain[:len_start] + bytes(new_len_bytes) + cs_body_plain[len_start + len_bytes:]

                logger.info(f"[TCP] 在 token 字段添加 padding: +{padding_needed} 字节，总长度：{len(cs_body_plain)}")
                logger.info(f"[TCP] token 长度：{current_len} -> {new_len} (varint 字节：{len_bytes} -> {len(new_len_bytes)})")
            else:
                logger.error("[TCP] 未找到 token 字段，无法添加 padding")
                raise ValueError("未找到 token 字段")

        cs_body = cs_body_plain
        encrypted = False

        # 输出明文前 32 字节用于调试
        logger.info(f"[TCP] CsLogin 明文前 32 字节：{cs_body_plain[:32].hex()}")
        logger.info(f"[TCP] CsLogin 明文长度：{len(cs_body_plain)}")

        if self.srsa_bridge is not None:
            try:
                cs_body = self.srsa_bridge.encrypt_login_body(cs_body_plain)
                encrypted = True
                logger.info(f"[TCP] SRSA 加密后前 16 字节：{cs_body[:16].hex()}")
                logger.info(f"[TCP] 是否包含 SRSA 头：{cs_body[:4] == SRSA_MAGIC}")
            except Exception as exc:
                logger.error(f"[TCP] SRSA 加密失败：{exc}")
                raise

        msgid = 13
        seq_id = self._seq_id
        self._seq_id += 1

        # 登录包包含 msgid 和 checksum
        # 使用抓包中的 checksum 值
        checksum = 428775019
        logger.info(f"[TCP] 使用 checksum: {checksum}")

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
