import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

try:
    import segno
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

PASSPORT_APP_CODE = "dd7b852d5f1dd9da"


def print_qrcode(url: str) -> None:
    """在终端中显示二维码"""
    if HAS_QRCODE:
        qr = segno.make(url, error="L")
        import sys
        import io
        buffer = io.StringIO()
        qr.terminal(out=buffer, compact=True)
        try:
            print(buffer.getvalue())
        except UnicodeEncodeError:
            print(f"二维码链接: {url}")
    else:
        print(f"二维码链接: {url}")
        print("提示: 安装 segno 库可显示二维码: pip install segno")


@dataclass
class DeviceInfo:
    device_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    device_model: str = "iPhone15,2"
    device_type: int = 0
    os_ver: str = "17.2"
    captcha_version: str = "4.0"
    user_agent: str = "Endfield/1 CFNetwork/3860.200.71 Darwin/25.2.0"
    
    def to_headers(self, cookie: str = "") -> dict[str, str]:
        headers = {
            "x-deviceid": self.device_id,
            "x-devicemodel": self.device_model,
            "x-devicetype": str(self.device_type),
            "x-osver": self.os_ver,
            "x-captcha-version": self.captcha_version,
            "user-agent": self.user_agent,
        }
        if cookie:
            headers["cookie"] = cookie
        return headers


@dataclass
class PassportLoginResult:
    token: str
    hgId: str
    deviceToken: str
    uid: str
    code: str
    channel_token: str


class PassportLogin:
    def __init__(self, timeout: float = 20.0, device_info: Optional[DeviceInfo] = None):
        self._timeout = timeout
        self._device_info = device_info or DeviceInfo()
        self._cookies: list[str] = []

    def _update_cookies(self, cookies: list[str]) -> None:
        self._cookies = cookies
    
    def _get_headers(self) -> dict[str, str]:
        cookie_str = "; ".join(self._cookies) if self._cookies else ""
        return self._device_info.to_headers(cookie_str)

    async def gen_scan_login(self, client: httpx.AsyncClient) -> tuple[str, str]:
        """获取扫码登录二维码"""
        url = "https://as.hypergryph.com/general/v1/gen_scan/login"
        headers = self._get_headers()
        data = {"appCode": PASSPORT_APP_CODE}
        r = await client.post(url, json=data, headers=headers)
        r.raise_for_status()
        result = r.json()
        
        if set_cookie := r.headers.get("set-cookie"):
            self._update_cookies([set_cookie])
        
        if result.get("status") != 0:
            raise RuntimeError(f"gen_scan_login failed: {result}")
        data_obj = result.get("data", {})
        return data_obj.get("scanId", ""), data_obj.get("scanUrl", "")

    async def poll_scan_status(self, client: httpx.AsyncClient, scan_id: str, timeout: float = 120.0) -> str:
        """轮询扫码状态"""
        start_time = time.time()
        url = f"https://as.hypergryph.com/general/v1/scan_status?scanId={scan_id}"
        
        while time.time() - start_time < timeout:
            headers = self._get_headers()
            r = await client.get(url, headers=headers)
            r.raise_for_status()
            result = r.json()
            status = result.get("status")
            
            if status == 100:
                await asyncio.sleep(2)
                continue
            elif status == 101:
                await asyncio.sleep(1)
                continue
            elif status == 0:
                return result.get("data", {}).get("scanCode", "")
            else:
                raise RuntimeError(f"scan_status unexpected: {result}")
        
        raise TimeoutError("Scan timeout")

    async def token_by_scan_code(self, client: httpx.AsyncClient, scan_code: str) -> tuple[str, str, str]:
        """使用scanCode获取token"""
        url = "https://as.hypergryph.com/user/auth/v1/token_by_scan_code"
        headers = self._get_headers()
        data = {
            "appCode": PASSPORT_APP_CODE,
            "scanCode": scan_code,
            "from": 1
        }
        r = await client.post(url, json=data, headers=headers)
        r.raise_for_status()
        result = r.json()
        if result.get("status") != 0:
            raise RuntimeError(f"token_by_scan_code failed: {result}")
        
        data_obj = result.get("data", {})
        return (
            data_obj.get("token", ""),
            data_obj.get("hgId", ""),
            data_obj.get("deviceToken", "")
        )

    async def oauth2_grant(self, client: httpx.AsyncClient, token: str, device_token: str) -> tuple[str, str]:
        """OAuth2鉴权获取code"""
        url = "https://as.hypergryph.com/user/oauth2/v2/grant"
        headers = self._get_headers()
        data = {
            "deviceToken": device_token,
            "type": 0,
            "token": token,
            "appCode": PASSPORT_APP_CODE
        }
        r = await client.post(url, json=data, headers=headers)
        r.raise_for_status()
        result = r.json()
        if result.get("status") != 0:
            raise RuntimeError(f"oauth2_grant failed: {result}")
        
        data_obj = result.get("data", {})
        return data_obj.get("uid", ""), data_obj.get("code", "")

    def build_channel_token(self, code: str) -> str:
        """构造channelToken"""
        return json.dumps({
            "type": 1,
            "isSuc": True,
            "code": code
        }, ensure_ascii=False, separators=(",", ":"))

    async def login(self) -> PassportLoginResult:
        """完整扫码登录流程"""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            scan_id, scan_url = await self.gen_scan_login(client)
            print("\n" + "="*50)
            print("请使用鹰角通行证APP扫描下方二维码登录")
            print("="*50)
            print_qrcode(scan_url)
            print("="*50 + "\n")
            
            scan_code = await self.poll_scan_status(client, scan_id)
            token, hg_id, device_token = await self.token_by_scan_code(client, scan_code)
            uid, code = await self.oauth2_grant(client, token, device_token)
            channel_token = self.build_channel_token(code)
            
            return PassportLoginResult(
                token=token,
                hgId=hg_id,
                deviceToken=device_token,
                uid=uid,
                code=code,
                channel_token=channel_token
            )


async def main():
    login = PassportLogin()
    result = await login.login()
    print(f"登录成功!")
    print(f"hgId: {result.hgId}")
    print(f"uid: {result.uid}")
    print(f"channel_token: {result.channel_token[:50]}...")


if __name__ == "__main__":
    asyncio.run(main())
