import struct
from typing import Any


def _encode_varint(value: int) -> bytes:
    """编码变长整数 (Protobuf varint)"""
    result = []
    while value > 127:
        result.append((value & 0x7f) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _encode_string(field_number: int, value: str) -> bytes:
    """编码字符串字段 (wire type 2)"""
    if not value:
        return b""
    field_tag = (field_number << 3) | 2  # wire type 2 = length-delimited
    encoded = value.encode("utf-8")
    return _encode_varint(field_tag) + _encode_varint(len(encoded)) + encoded


def _encode_int32(field_number: int, value: int) -> bytes:
    """编码int32字段 (wire type 0)"""
    if value == 0:
        return b""
    field_tag = (field_number << 3) | 0  # wire type 0 = varint
    return _encode_varint(field_tag) + _encode_varint(value)


def _encode_enum(field_number: int, value: int) -> bytes:
    """编码枚举字段 (wire type 0, 当作int32处理)"""
    return _encode_int32(field_number, value)


def build_login_plain(ctx: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    """
    构建登录明文消息体 (CsLogin Protobuf格式)
    
    根据 Campofinale.proto 中 CsLogin 的定义:
    - string channel = 1;
    - string client_res_version = 2;
    - string client_version = 3;
    - string uid = 5;
    - string token = 6;
    - string client_public_key = 7;
    - ClientPlatformType platform_id = 8;
    - AreaType area = 9;
    - EnvType env = 12;
    - int32 client_language = 16;
    
    返回: (登录消息二进制protobuf, 上下文字典)
    """
    uid = str(ctx.get("uid") or ctx.get("a1") or "")
    token = str(ctx.get("token") or ctx.get("a2") or "")
    client_version = str(ctx.get("client_version") or ctx.get("a6") or "1.0.14")
    client_res_version = str(ctx.get("client_res_version") or ctx.get("a7") or "")
    channel = str(ctx.get("channel") or "")
    client_public_key = str(ctx.get("client_public_key") or "")
    
    platform_id = int(ctx.get("platform_id") or ctx.get("a9") or 3)
    area = int(ctx.get("area") or ctx.get("a10") or 0)
    env = int(ctx.get("env") or ctx.get("a11") or 2)
    client_language = int(ctx.get("client_language") or 0)
    
    # 按照字段编号顺序构建protobuf消息
    # 注意：proto3中，默认值（0, "", false）不会被编码
    parts = []
    
    # field 1: string channel
    if channel:
        parts.append(_encode_string(1, channel))
    
    # field 2: string client_res_version
    if client_res_version:
        parts.append(_encode_string(2, client_res_version))
    
    # field 3: string client_version
    if client_version:
        parts.append(_encode_string(3, client_version))
    
    # field 5: string uid
    if uid:
        parts.append(_encode_string(5, uid))
    
    # field 6: string token
    if token:
        parts.append(_encode_string(6, token))
    
    # field 7: string client_public_key
    if client_public_key:
        parts.append(_encode_string(7, client_public_key))
    
    # field 8: ClientPlatformType platform_id (enum as int32)
    if platform_id != 0:
        parts.append(_encode_enum(8, platform_id))
    
    # field 9: AreaType area (enum as int32)
    if area != 0:
        parts.append(_encode_enum(9, area))
    
    # field 12: EnvType env (enum as int32)
    if env != 0:
        parts.append(_encode_enum(12, env))
    
    # field 16: int32 client_language
    if client_language != 0:
        parts.append(_encode_int32(16, client_language))
    
    plain_bytes = b"".join(parts)
    return plain_bytes, ctx


def parse_login_response(response_data: bytes) -> dict[str, Any]:
    """解析登录响应 (ScLogin) - 简化版JSON解析"""
    import json
    try:
        return json.loads(response_data.decode("utf-8"))
    except Exception:
        return {"raw": response_data.hex()[:100]}


if __name__ == "__main__":
    ctx = {
        "uid": "247368550",
        "token": "test_token",
        "client_version": "1.0.14",
        "platform_id": 3,
        "area": 0,
        "env": 2,
    }
    plain, ctx = build_login_plain(ctx)
    print(f"Login plain hex: {plain.hex()}")
    print(f"Length: {len(plain)} bytes")
