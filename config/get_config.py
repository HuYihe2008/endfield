import argparse
import base64
import json
import os
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ENDFIELD_RC_KEY_B64_OVERSEA = "cZm86UfDp/kgJ3agKx+HZA=="
ENDFIELD_RC_KEY_B64_CN = "Wgxugl5qVirx7r3km6nXtA=="

ENDFIELD_U8_AES_KEY_HEX = "C0F30E1CE763BBC21CC355A34303AC50399444BFF68C4A22AF398C0A166EE143"
ENDFIELD_U8_AES_IV_HEX = "33467861192750649501937264608400"


LAUNCHER_VERSION_URL = (
    "https://launcher.hypergryph.com/api/game/get_latest"
    "?appcode=6LL0KJuqHBVz33WK&channel=1&platform={device}&sub_channel=1&source=game"
)
RES_VERSION_URL = (
    "https://launcher.hypergryph.com/api/game/get_latest_resources"
    "?appcode=6LL0KJuqHBVz33WK&platform={device}&game_version=1.0&version={version}&rand_str={rand_str}"
)

ENGINE_CONFIG_URL = "https://game-config.hypergryph.com/api/remote_config/3/prod-engine/default/{device}/engine_config"
NETWORK_CONFIG_URL = "https://game-config.hypergryph.com/api/remote_config/v2/3/prod-obt/default/{device}/network_config"
GAME_CONFIG_URL = "https://game-config.hypergryph.com/api/remote_config/v2/3/prod-obt/default/{device}/game_config"


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > 16:
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]


def _aes_cbc_decrypt(cipher: bytes, key: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(cipher) + decryptor.finalize()


def _decrypt_remote_config_text(ciphertext_b64: str, *, is_oversea: bool) -> str:
    key_b64 = ENDFIELD_RC_KEY_B64_OVERSEA if is_oversea else ENDFIELD_RC_KEY_B64_CN
    if not key_b64:
        raise RuntimeError("Missing env var: ENDFIELD_RC_KEY_B64_OVERSEA / ENDFIELD_RC_KEY_B64_CN")

    raw = base64.b64decode(ciphertext_b64)
    iv, cipher = raw[:16], raw[16:]
    key = base64.b64decode(key_b64)

    pt = _aes_cbc_decrypt(cipher, key, iv)
    pt = _pkcs7_unpad(pt)
    return pt.decode("utf-8")


def _decrypt_u8_extra_config_bin(cipher: bytes) -> bytes:
    key_hex = ENDFIELD_U8_AES_KEY_HEX
    iv_hex = ENDFIELD_U8_AES_IV_HEX

    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)

    pt = _aes_cbc_decrypt(cipher, key, iv)
    return _pkcs7_unpad(pt)


@dataclass
class ConfigResult:
    launcher_version: dict[str, Any]
    res_version: dict[str, Any]
    engine_config: dict[str, Any]
    network_config: dict[str, Any]
    game_config: dict[str, Any]


class EndfieldConfigFetcher:
    def __init__(self, *, timeout: float = 20.0, is_oversea: bool = False):
        self._timeout = timeout
        self._is_oversea = is_oversea

    def _get_text(self, url: str) -> str:
        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            r = client.get(url)
            r.raise_for_status()
            return r.text

    def _get_json(self, url: str) -> dict[str, Any]:
        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            r = client.get(url)
            r.raise_for_status()
            return r.json()

    def get_launcher_version(self, device: str) -> dict[str, Any]:
        return self._get_json(LAUNCHER_VERSION_URL.format(device=device))

    def get_u8_extra_config(self, file_path: str) -> dict[str, Any]:
        url = file_path.rstrip("/") + "/U8Data/config/u8ExtraConfig.bin"
        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            r = client.get(url)
            r.raise_for_status()
            raw = r.content

        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            pt = _decrypt_u8_extra_config_bin(raw)
            return json.loads(pt.decode("utf-8"))

    def get_res_version(self, device: str, version: str, rand_str: str) -> dict[str, Any]:
        url = RES_VERSION_URL.format(device=device, version=version, rand_str=rand_str)
        return self._get_json(url)

    def _get_remote_config(self, url: str) -> dict[str, Any]:
        text = self._get_text(url)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            decrypted = _decrypt_remote_config_text(text, is_oversea=self._is_oversea)
            return json.loads(decrypted)

    def get_engine_config(self, device: str) -> dict[str, Any]:
        return self._get_json(ENGINE_CONFIG_URL.format(device="default"))

    def get_network_config(self, device: str) -> dict[str, Any]:
        return self._get_remote_config(NETWORK_CONFIG_URL.format(device="default"))

    def get_game_config(self, device: str) -> dict[str, Any]:
        return self._get_remote_config(GAME_CONFIG_URL.format(device=device))

    def fetch_all(self, device: str) -> ConfigResult:
        launcher = self.get_launcher_version(device)

        version = launcher.get("version", "")
        pkg = launcher.get("pkg") or {}
        file_path = pkg.get("file_path") or ""
        if not version or not file_path:
            raise RuntimeError(f"launcher_version missing version/file_path: version={version!r} file_path={file_path!r}")

        u8_cfg = self.get_u8_extra_config(file_path)
        rand_str = u8_cfg.get("randStr") or u8_cfg.get("rand_str") or ""
        if not rand_str:
            raise RuntimeError("u8ExtraConfig.bin decrypted but randStr missing")

        res_version = self.get_res_version(device, version, rand_str)
        engine = self.get_engine_config(device)
        network = self.get_network_config(device)
        game = self.get_game_config(device)

        return ConfigResult(
            launcher_version=launcher,
            res_version=res_version,
            engine_config=engine,
            network_config=network,
            game_config=game,
        )


def _dump(out_dir: str, name: str, obj: Any) -> None:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def main():
    device = "Windows"
    oversea = False
    outdir = "D:/Develop/Other/python/endfield/tmp"

    fetcher = EndfieldConfigFetcher(is_oversea=oversea)
    result = fetcher.fetch_all(device)

    print("launcher_version.version =", result.launcher_version.get("version"))
    print("network_config keys =", list(result.network_config.keys())[:10])
    print("game_config keys =", list(result.game_config.keys())[:10])

    if outdir:
        _dump(outdir, "launcher_version", result.launcher_version)
        _dump(outdir, "res_version", result.res_version)
        _dump(outdir, "engine_config", result.engine_config)
        _dump(outdir, "network_config", result.network_config)
        _dump(outdir, "game_config", result.game_config)
        print("saved to", outdir)


if __name__ == "__main__":
    main()
