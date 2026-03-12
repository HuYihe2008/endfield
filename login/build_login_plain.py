from typing import Any

try:
    from ..tcp.tcp import build_cs_login_body
except ImportError:
    from tcp.tcp import build_cs_login_body


def build_login_plain(ctx: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    """复用 TCP 主路径的 CsLogin 编码逻辑，避免出现两份不一致实现。"""
    return build_cs_login_body(ctx)


def parse_login_response(response_data: bytes) -> dict[str, Any]:
    """解析登录响应 (ScLogin) - 简化版 JSON 解析"""
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
        "a21": 1,
        "a22": 1,
    }
    plain, meta = build_login_plain(ctx)
    print(f"Login plain hex: {plain.hex()}")
    print(f"Length: {len(plain)} bytes")
    print(f"Fields: {meta.get('field_order')}")
