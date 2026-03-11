import json
from dataclasses import dataclass
from typing import Any, Optional

import httpx

U8_APP_CODE = "4df8f5a7c2ad711b497a"
CHANNEL_MASTER_ID = "1"


@dataclass
class U8LoginResult:
    token: str
    uid: str
    servers: list[dict[str, Any]]
    grant_code: str


class U8Login:
    def __init__(self, timeout: float = 20.0):
        self._timeout = timeout

    async def token_by_channel_token(self, client: httpx.AsyncClient, channel_token: str) -> tuple[str, str]:
        """Unity用户鉴权"""
        url = "https://u8.hypergryph.com/u8/user/auth/v2/token_by_channel_token"
        data = {
            "appCode": U8_APP_CODE,
            "channelMasterId": CHANNEL_MASTER_ID,
            "channelToken": channel_token,
            "type": 0,
            "platform": 0
        }
        r = await client.post(url, json=data)
        r.raise_for_status()
        result = r.json()
        
        if result.get("status") != 0:
            raise RuntimeError(f"token_by_channel_token failed: {result}")
        
        data_obj = result.get("data", {})
        return data_obj.get("token", ""), data_obj.get("uid", "")

    async def server_list(self, client: httpx.AsyncClient, token: str) -> list[dict[str, Any]]:
        """获取服务器列表"""
        url = "https://u8.hypergryph.com/game/server/v1/server_list"
        data = {"token": token}
        r = await client.post(url, json=data)
        r.raise_for_status()
        result = r.json()
        
        if result.get("status") != 0:
            raise RuntimeError(f"server_list failed: {result}")
        
        return result.get("data", {}).get("serverList", [])

    async def grant(self, client: httpx.AsyncClient, token: str) -> str:
        """Unity Grant获取授权码"""
        url = "https://u8.hypergryph.com/u8/user/auth/v2/grant"
        data = {
            "token": token,
            "type": 0,
            "platform": 0
        }
        r = await client.post(url, json=data)
        r.raise_for_status()
        result = r.json()
        
        if result.get("status") != 0:
            raise RuntimeError(f"grant failed: {result}")
        
        return result.get("data", {}).get("code", "")

    async def confirm_server(self, client: httpx.AsyncClient, token: str, server_id: str) -> None:
        """确认登录服务器"""
        url = "https://u8.hypergryph.com/game/role/v1/confirm_server"
        data = {
            "token": token,
            "serverId": server_id
        }
        r = await client.post(url, json=data)
        r.raise_for_status()
        result = r.json()
        
        if result.get("status") != 0:
            raise RuntimeError(f"confirm_server failed: {result}")

    async def login(self, channel_token: str) -> U8LoginResult:
        """完整Unity登录流程"""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            token, uid = await self.token_by_channel_token(client, channel_token)
            servers = await self.server_list(client, token)
            grant_code = await self.grant(client, token)
            
            return U8LoginResult(
                token=token,
                uid=uid,
                servers=servers,
                grant_code=grant_code
            )


async def main():
    channel_token = '{"type":1,"isSuc":true,"code":"test"}'
    login = U8Login()
    result = await login.login(channel_token)
    print(f"Unity登录成功!")
    print(f"uid: {result.uid}")
    print(f"servers: {len(result.servers)}")
    print(f"grant_code: {result.grant_code[:50]}...")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
