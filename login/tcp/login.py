import asyncio
import json
from pathlib import Path
from typing import Any, Optional

from ...tcp.srsa_bridge import SRSABridge
from ..build_login_plain import build_login_plain


CS_LOGIN_MSG_ID = 50001
SC_LOGIN_MSG_ID = 50002


class TCPLogin:
    def __init__(self, dll_dir: Path):
        self._srsa_bridge = SRSABridge(dll_dir)

    def encrypt_login_body(self, plain: bytes) -> bytes:
        return self._srsa_bridge.encrypt_login_body(plain)

    def decrypt_login_body(self, encrypted_body: bytes) -> bytes:
        return self._srsa_bridge.decrypt_login_body(encrypted_body)

    def try_decrypt_login_body(self, encrypted_body: bytes) -> Optional[bytes]:
        return self._srsa_bridge.try_decrypt_login_body(encrypted_body)

    def build_login_packet(self, ctx: dict[str, Any]) -> bytes:
        """构建登录数据包"""
        import struct
        
        plain_body, _ = build_login_plain(ctx)
        encrypted_body = self.encrypt_login_body(plain_body)
        
        full_body = struct.pack(">I", CS_LOGIN_MSG_ID) + encrypted_body
        length = len(full_body)
        header = struct.pack(">I", length)[1:]
        
        return header + full_body

    def parse_login_response(self, data: bytes) -> dict[str, Any]:
        """解析登录响应"""
        decrypted = self.try_decrypt_login_body(data)
        if decrypted is None:
            decrypted = data
        
        try:
            return json.loads(decrypted.decode("utf-8"))
        except Exception:
            return {}


__all__ = ["TCPLogin"]
