import argparse
import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Optional

from config.get_config import EndfieldConfigFetcher
from login.passport_login import PassportLogin, PassportLoginResult
from login.u8_login import U8Login, U8LoginResult
from tcp.srsa_bridge import SRSABridge
from tcp.tcp import TCPClient

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


class EndfieldClient:
    def __init__(self, dll_dir: Path, config_dir: Optional[Path] = None, is_oversea: bool = False, qrcode_dir: Optional[Path] = None):
        self.dll_dir = dll_dir
        self.config_dir = config_dir
        self.is_oversea = is_oversea
        self.qrcode_dir = qrcode_dir

        self._config: Optional[dict[str, Any]] = None
        self._passport_result: Optional[PassportLoginResult] = None
        self._u8_result: Optional[U8LoginResult] = None
        self._srsa_bridge: Optional[SRSABridge] = None
        self._tcp_client: Optional[TCPClient] = None

    async def fetch_config(self, device: str = "Windows") -> dict[str, Any]:
        """获取游戏配置"""
        logger.info("[Config] 开始获取游戏配置...")
        fetcher = EndfieldConfigFetcher(is_oversea=self.is_oversea)
        result = fetcher.fetch_all(device)

        self._config = {
            "launcher_version": result.launcher_version,
            "res_version": result.res_version,
            "engine_config": result.engine_config,
            "network_config": result.network_config,
            "game_config": result.game_config,
        }

        if self.config_dir:
            self._save_config()

        logger.info("[Config] 配置获取完成")
        return self._config

    def _save_config(self) -> None:
        """保存配置到文件"""
        if not self.config_dir or not self._config:
            return

        self.config_dir.mkdir(parents=True, exist_ok=True)
        for name, data in self._config.items():
            path = self.config_dir / f"{name}.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"[Config] 配置已保存到 {self.config_dir}")

    async def passport_login(self) -> PassportLoginResult:
        """鹰角通行证扫码登录"""
        logger.info("[Passport] 开始鹰角通行证登录...")
        login = PassportLogin(qrcode_dir=str(self.qrcode_dir) if self.qrcode_dir else None)
        self._passport_result = await login.login()
        logger.info(f"[Passport] 登录成功，hgId: {self._passport_result.hgId}")
        return self._passport_result

    async def u8_login(self, channel_token: str) -> U8LoginResult:
        """Unity 用户认证"""
        logger.info("[U8] 开始 Unity 用户认证...")
        login = U8Login()
        self._u8_result = await login.login(channel_token)
        logger.info(f"[U8] 认证成功，uid: {self._u8_result.uid}")

        if self._u8_result.servers:
            logger.info(f"[U8] 可用服务器：{len(self._u8_result.servers)}")
            for server in self._u8_result.servers[:3]:
                logger.info(f"  - {server.get('serverName')}: {server.get('serverId')}")

        return self._u8_result

    def get_server(self, server_id: Optional[str] = None) -> dict[str, Any]:
        """获取服务器信息"""
        if not self._u8_result or not self._u8_result.servers:
            raise RuntimeError("请先完成 U8 登录")

        if server_id:
            for server in self._u8_result.servers:
                if server.get("serverId") == server_id:
                    return server

        for server in self._u8_result.servers:
            if server.get("defaultChoose"):
                return server

        return self._u8_result.servers[0]

    def init_srsa(self) -> SRSABridge:
        """初始化 SRSA 加密桥接"""
        logger.info("[SRSA] 初始化 SRSA 加密桥接...")
        self._srsa_bridge = SRSABridge(self.dll_dir)
        logger.info(f"[SRSA] SRSA 版本：{self._srsa_bridge.version}")
        return self._srsa_bridge

    def get_client_version(self) -> str:
        """从配置获取客户端版本"""
        if self._config and "launcher_version" in self._config:
            version = self._config["launcher_version"].get("version", "")
            if version:
                return version
        return "1.0.14"  # 默认版本

    async def tcp_login(self, host: str, port: int, uid: str, grant_code: str) -> Any:
        """TCP 连接并登录"""
        logger.info(f"[TCP] 连接到 {host}:{port}...")
        self._tcp_client = TCPClient(self.dll_dir)

        await self._tcp_client.connect(host, port)
        logger.info("[TCP] 连接成功，开始登录...")

        client_version = self.get_client_version()
        logger.info(f"[TCP] 使用客户端版本：{client_version}")

        login_ctx = {
            "config": self._config or {},
            "passport_device_token": self._passport_result.deviceToken if self._passport_result else "",
            "device_token": self._passport_result.deviceToken if self._passport_result else "",
            "channel_master_id": 1,
        }

        login_response = await self._tcp_client.login(
            uid=uid,
            grant_code=grant_code,
            client_version=client_version,
            platform_id=3,
            area=0,
            env=2,
            login_ctx=login_ctx,
        )

        logger.info(f"[TCP] 登录成功！server_time: {login_response.server_time}")
        logger.info(f"[TCP] uid: {login_response.uid}")

        return login_response


async def main():
    parser = argparse.ArgumentParser(description="Endfield 无头客户端")
    parser.add_argument("--dll-dir", type=Path, required=True, help="GameAssembly.dll 所在目录")
    parser.add_argument("--config-dir", type=Path, default=Path(__file__).parent / "Data" / "tmp", help="配置保存目录")
    parser.add_argument("--skip-config", action="store_true", help="跳过配置获取")
    parser.add_argument("--oversea", action="store_true", help="使用海外服务器")
    parser.add_argument("--server-id", type=str, help="指定服务器 ID")
    parser.add_argument("--qrcode-dir", type=Path, help="二维码图片保存目录 (默认：./qrcode)")

    args = parser.parse_args()

    # 默认二维码保存目录
    if args.qrcode_dir is None:
        args.qrcode_dir = Path(__file__).parent / "qrcode"

    client = EndfieldClient(
        dll_dir=args.dll_dir,
        config_dir=args.config_dir,
        is_oversea=args.oversea,
        qrcode_dir=args.qrcode_dir
    )

    if not args.skip_config:
        await client.fetch_config()
    else:
        logger.info("[Config] 跳过配置获取")

    await client.passport_login()
    await client.u8_login(client._passport_result.channel_token)

    server = client.get_server(args.server_id)
    logger.info(f"[Server] 选择服务器：{server.get('serverName')}")

    host_port = json.loads(server.get("serverDomain", "[]"))
    if host_port:
        host = host_port[0].get("host")
        port = host_port[0].get("port")
        logger.info(f"[TCP] 服务器地址：{host}:{port}")

    client.init_srsa()

    login_response = await client.tcp_login(
        host=host,
        port=port,
        uid=client._u8_result.uid,
        grant_code=client._u8_result.grant_code
    )

    logger.info("[Client] 登录流程完成!")


if __name__ == "__main__":
    asyncio.run(main())
