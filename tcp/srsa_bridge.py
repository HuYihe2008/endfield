import ctypes
import os
import struct
from pathlib import Path
from typing import Optional

SRSA_MAGIC = b"\x05\x0f\x09\x0c"
SRSA_HEADER_LEN = 16  # magic(4) + encrypted_len(4) + plain_len(4) + unknown(4)


class SRSABridgeError(Exception):
    pass


class SRSABridge:
    """
    SRSA 加密桥接

    根据 IL2CPP 分析，SRSA 使用 IFix 热修复框架，加密逻辑可能已被修改。
    s_keyLength = 178 字节，不是标准 RSA 密钥长度。
    """
    def __init__(self, dll_dir: Path) -> None:
        self.dll_dir = dll_dir
        os.add_dll_directory(str(dll_dir))
        self._dll = ctypes.WinDLL(str(dll_dir / "GameAssembly.dll"))

        self._get_ver = self._dll.mono_method_h_get_ver
        self._get_ver.argtypes = []
        self._get_ver.restype = ctypes.c_uint64

        self._get_code = self._dll.mono_method_h_get_code
        self._get_code.argtypes = [ctypes.c_uint64, ctypes.c_uint32]
        self._get_code.restype = ctypes.c_uint64

        self._set_code = self._dll.mono_method_h_set_code
        self._set_code.argtypes = [ctypes.c_uint64]
        self._set_code.restype = ctypes.c_uint64

        self._remove_code = self._dll.mono_method_h_remove_code
        self._remove_code.argtypes = [ctypes.c_uint64]
        self._remove_code.restype = None

        # 尝试获取 SRSA 方法
        self._test_method = None
        self._load_from_file = None

        # 尝试获取 test 方法
        try:
            self._test_method = self._dll.SRSA_test
            self._test_method.argtypes = []
            self._test_method.restype = None
        except AttributeError:
            pass

        # 尝试获取 LoadFromFile 方法（需要 Span<byte> 参数，较难调用）
        try:
            # 可能需要调用内部方法
            pass
        except AttributeError:
            pass

        # 调用 test 方法初始化
        if self._test_method:
            try:
                self._test_method()
            except Exception as e:
                pass

    @property
    def version(self) -> int:
        return int(self._get_ver())

    def encrypt_login_body(self, plain: bytes) -> bytes:
        """
        加密登录 body

        SRSA 加密输出格式：
        - 4 字节 magic: 05 0f 09 0c
        - 4 字节 total_len (小端)
        - 4 字节 plain_len (小端)
        - 4 字节 unknown: 139 (0x8b)
        - 实际加密数据
        """
        C_GET = 0x8F6650A485
        C_RET = 0x0F91A4399A0
        HANDLE_MIN = 0x100000
        MAX_LEN = 0x100000

        src = (ctypes.c_ubyte * len(plain)).from_buffer_copy(plain)
        ptr = ctypes.cast(src, ctypes.c_void_p).value
        if ptr is None:
            raise SRSABridgeError("encrypt ptr is null")

        handle = self._get_code(ptr ^ C_GET, len(plain))
        if handle < HANDLE_MIN:
            raise SRSABridgeError(f"mono_method_h_get_code failed code={handle}")

        try:
            decoded_ptr = handle ^ C_RET
            out_len = ctypes.c_int32.from_address(decoded_ptr + 4).value
            if out_len <= 0 or out_len > MAX_LEN:
                raise SRSABridgeError(f"encrypt out_len invalid: {out_len}")

            encrypted_data = ctypes.string_at(decoded_ptr, out_len)

            # 构建 SRSA 头部
            srsa_header = SRSA_MAGIC
            srsa_header += struct.pack("<I", out_len)  # total_len
            srsa_header += struct.pack("<I", len(plain))  # plain_len
            srsa_header += struct.pack("<I", 139)  # unknown

            return srsa_header + encrypted_data
        finally:
            self._remove_code(handle)

    def decrypt_login_body(self, encrypted_body: bytes) -> bytes:
        """
        解密登录 body

        参数:
            encrypted_body: SRSA 加密数据（包含 SRSA 头部）

        返回:
            解密后的明文
        """
        C_SET = 0x971AB5C8FF
        C_RET = 0x0F91A4399A0
        HANDLE_MIN = 0x100000
        MAX_LEN = 0x100000

        # 跳过 SRSA 头部（16 字节）
        if len(encrypted_body) >= SRSA_HEADER_LEN and encrypted_body[:4] == SRSA_MAGIC:
            encrypted_data = encrypted_body[SRSA_HEADER_LEN:]
        else:
            encrypted_data = encrypted_body

        src = (ctypes.c_ubyte * len(encrypted_data)).from_buffer_copy(encrypted_data)
        ptr = ctypes.cast(src, ctypes.c_void_p).value
        if ptr is None:
            raise SRSABridgeError("decrypt ptr is null")

        handle = self._set_code(ptr ^ C_SET)
        if handle < HANDLE_MIN:
            raise SRSABridgeError(f"mono_method_h_set_code failed code={handle}")

        try:
            decoded_ptr = handle ^ C_RET
            out_len = ctypes.c_int32.from_address(decoded_ptr).value
            if out_len < 0 or out_len > MAX_LEN:
                raise SRSABridgeError(f"decrypt out_len invalid: {out_len}")
            return ctypes.string_at(decoded_ptr + 4, out_len)
        finally:
            self._remove_code(handle)

    def try_decrypt_login_body(self, encrypted_body: bytes) -> Optional[bytes]:
        try:
            return self.decrypt_login_body(encrypted_body)
        except Exception:
            return None
