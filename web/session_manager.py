from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from main import EndfieldClient
from plugins import BlueprintQueryPlugin, PluginManager, ShopPriceQueryPlugin

logger = logging.getLogger(__name__)


@dataclass
class SessionState:
    stage: str = "idle"
    message: str = "尚未建立会话"
    ready: bool = False
    login_task_running: bool = False
    uid: str = ""
    server_id: str = ""
    server_name: str = ""
    host: str = ""
    port: int = 0
    qrcode_path: Optional[str] = None
    qrcode_image_url: Optional[str] = None
    scan_url: Optional[str] = None
    oversea: bool = False
    skip_config: bool = False
    error: Optional[str] = None
    available_plugins: list[dict[str, Any]] = field(default_factory=list)
    last_blueprint_query: Optional[dict[str, Any]] = None
    last_shop_price_state: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EndfieldSessionManager:
    def __init__(
        self,
        *,
        dll_dir: Path,
        config_dir: Optional[Path] = None,
        qrcode_dir: Optional[Path] = None,
        tcp_options: Optional[dict[str, Any]] = None,
    ):
        self.dll_dir = Path(dll_dir)
        self.config_dir = Path(config_dir) if config_dir else None
        self.qrcode_dir = Path(qrcode_dir) if qrcode_dir else (Path(__file__).resolve().parent.parent / "qrcode")
        self.tcp_options = dict(tcp_options or {})

        self._client: Optional[EndfieldClient] = None
        self._plugin_manager: Optional[PluginManager] = None
        self._login_task: Optional[asyncio.Task[None]] = None
        self._lock = asyncio.Lock()
        self._state = SessionState()

        self.qrcode_dir.mkdir(parents=True, exist_ok=True)

    def _set_state(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            setattr(self._state, key, value)

    def _refresh_runtime_state(self) -> None:
        self._state.login_task_running = bool(self._login_task and not self._login_task.done())

        if not self._client or not self._client._passport_login_driver:
            return

        driver = self._client._passport_login_driver
        if driver.last_qrcode_path:
            qrcode_path = Path(driver.last_qrcode_path)
            self._state.qrcode_path = str(qrcode_path)
            self._state.qrcode_image_url = f"/qrcode/{qrcode_path.name}"
        if driver.last_scan_url:
            self._state.scan_url = driver.last_scan_url

    def snapshot(self) -> dict[str, Any]:
        self._refresh_runtime_state()
        return self._state.to_dict()

    async def start_login(
        self,
        *,
        skip_config: bool = False,
        oversea: bool = False,
        server_id: Optional[str] = None,
    ) -> dict[str, Any]:
        async with self._lock:
            if self._login_task and not self._login_task.done():
                raise RuntimeError("已有登录流程正在执行")

            await self._close_unlocked(reset_state=False)

            self._state = SessionState(
                stage="starting",
                message="准备开始登录流程",
                ready=False,
                login_task_running=True,
                oversea=bool(oversea),
                skip_config=bool(skip_config),
                available_plugins=[],
                last_blueprint_query=self._state.last_blueprint_query,
                last_shop_price_state=self._state.last_shop_price_state,
            )

            self._client = EndfieldClient(
                dll_dir=self.dll_dir,
                config_dir=self.config_dir,
                is_oversea=bool(oversea),
                qrcode_dir=self.qrcode_dir,
                tcp_options=self.tcp_options,
            )
            self._login_task = asyncio.create_task(
                self._login_flow(
                    skip_config=bool(skip_config),
                    oversea=bool(oversea),
                    server_id=server_id,
                )
            )

        return self.snapshot()

    async def _login_flow(self, *, skip_config: bool, oversea: bool, server_id: Optional[str]) -> None:
        assert self._client is not None
        client = self._client

        try:
            if not skip_config:
                self._set_state(stage="fetch_config", message="正在拉取配置")
                await client.fetch_config()
            else:
                self._set_state(stage="fetch_config", message="跳过配置拉取")

            self._set_state(
                stage="waiting_scan",
                message="等待扫码登录",
                oversea=bool(oversea),
                skip_config=bool(skip_config),
            )
            await client.passport_login()

            self._set_state(stage="u8_login", message="正在进行 U8 鉴权")
            assert client._passport_result is not None
            await client.u8_login(client._passport_result.channel_token)

            server = client.get_server(server_id)
            host_port = json.loads(server.get("serverDomain", "[]"))
            if not host_port:
                raise RuntimeError("未获取到服务器地址")

            host = host_port[0].get("host")
            port = int(host_port[0].get("port"))
            if not host:
                raise RuntimeError("服务器 host 为空")

            self._set_state(
                stage="tcp_login",
                message="正在建立 TCP 会话",
                uid=client._u8_result.uid if client._u8_result else "",
                server_id=str(server.get("serverId") or ""),
                server_name=str(server.get("serverName") or ""),
                host=str(host),
                port=port,
            )

            client.init_srsa()
            await client.tcp_login(
                host=str(host),
                port=port,
                uid=client._u8_result.uid if client._u8_result else "",
                grant_code=client._u8_result.grant_code if client._u8_result else "",
            )

            self._plugin_manager = client.init_plugins()

            self._set_state(
                stage="ready",
                message="会话已建立，插件可用",
                ready=True,
                error=None,
                qrcode_path=self._state.qrcode_path,
                qrcode_image_url=self._state.qrcode_image_url,
                scan_url=self._state.scan_url,
                available_plugins=self._plugin_manager.describe(),
            )
        except asyncio.CancelledError:
            self._set_state(
                stage="idle",
                message="登录流程已取消",
                ready=False,
                error=None,
                available_plugins=[],
            )
            raise
        except Exception as exc:
            logger.exception("[WEB] 登录流程失败: %s", exc)
            self._set_state(
                stage="error",
                message="登录流程失败",
                ready=False,
                error=str(exc),
                available_plugins=[],
            )
            await client.close()
            self._plugin_manager = None
        finally:
            self._refresh_runtime_state()

    async def query_shared_blueprint(self, share_code: str, *, timeout: float = 10.0) -> dict[str, Any]:
        if not self._state.ready or not self._plugin_manager:
            raise RuntimeError("会话未就绪，请先完成登录")

        plugin = self._plugin_manager.get("blueprint-query")
        if not isinstance(plugin, BlueprintQueryPlugin):
            raise RuntimeError("blueprint-query plugin 未初始化")

        result = await plugin.query_shared_blueprint(share_code, timeout=timeout)
        self._state.last_blueprint_query = result
        return result

    def _get_shop_price_plugin(self) -> ShopPriceQueryPlugin:
        if not self._state.ready or not self._plugin_manager:
            raise RuntimeError("会话未就绪，请先完成登录")

        plugin = self._plugin_manager.get("shop-price-query")
        if not isinstance(plugin, ShopPriceQueryPlugin):
            raise RuntimeError("shop-price-query plugin 未初始化")
        return plugin

    async def get_shop_price_state(self) -> dict[str, Any]:
        plugin = self._get_shop_price_plugin()
        state = plugin.get_state()
        self._state.last_shop_price_state = state
        return state

    async def get_shop_price_domainshops(self) -> dict[str, Any]:
        plugin = self._get_shop_price_plugin()
        summary = plugin.get_domainshop_summary()
        state = plugin.get_state()
        self._state.last_shop_price_state = state
        return summary

    async def read_domain_development_versions(
        self,
        chapter_id: Optional[str] = None,
        *,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        plugin = self._get_shop_price_plugin()
        result = await plugin.read_domain_development_versions(chapter_id, timeout=timeout)
        self._state.last_shop_price_state = result.get("state")
        return result

    async def observe_domain_development(self, *, timeout: float = 10.0) -> dict[str, Any]:
        plugin = self._get_shop_price_plugin()
        result = await plugin.observe_domain_development(timeout=timeout)
        self._state.last_shop_price_state = result.get("state")
        return result

    async def change_current_domain(self, domain_id: str, *, timeout: float = 10.0) -> dict[str, Any]:
        plugin = self._get_shop_price_plugin()
        result = await plugin.change_current_domain(domain_id, timeout=timeout)
        self._state.last_shop_price_state = result.get("state")
        return result

    async def enter_shop(
        self,
        domain_id: Optional[str] = None,
        *,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        plugin = self._get_shop_price_plugin()
        result = await plugin.enter_shop(domain_id, timeout=timeout)
        self._state.last_shop_price_state = result.get("state")
        return result

    async def observe_shop_sync(self, *, timeout: float = 10.0) -> dict[str, Any]:
        plugin = self._get_shop_price_plugin()
        result = await plugin.observe_shop_sync(timeout=timeout)
        self._state.last_shop_price_state = result.get("state")
        return result

    async def observe_inbound_messages(
        self,
        *,
        timeout: float = 10.0,
        msgid: Optional[int] = None,
    ) -> dict[str, Any]:
        plugin = self._get_shop_price_plugin()
        result = await plugin.observe_inbound_messages(timeout=timeout, msgid=msgid)
        self._state.last_shop_price_state = result.get("state")
        return result

    async def query_friend_goods_price(
        self,
        shop_id: str,
        goods_id: str,
        role_ids: list[int],
        *,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        plugin = self._get_shop_price_plugin()
        result = await plugin.query_friend_goods_price(
            shop_id,
            goods_id,
            role_ids,
            timeout=timeout,
        )
        self._state.last_shop_price_state = result.get("state")
        return result

    async def query_friend_shop(
        self,
        friend_role_id: int,
        shop_ids: list[str],
        *,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        plugin = self._get_shop_price_plugin()
        result = await plugin.query_friend_shop(
            friend_role_id,
            shop_ids,
            timeout=timeout,
        )
        self._state.last_shop_price_state = result.get("state")
        return result

    async def update_domain_shop_binding(
        self,
        domain_id: str,
        shop_id: str,
        *,
        channel_id: Optional[str] = None,
        preferred: bool = True,
        note: Optional[str] = None,
    ) -> dict[str, Any]:
        plugin = self._get_shop_price_plugin()
        result = await plugin.update_domain_shop_binding(
            domain_id,
            shop_id,
            channel_id=channel_id,
            preferred=preferred,
            note=note,
        )
        self._state.last_shop_price_state = result.get("state")
        return result

    async def close(self) -> dict[str, Any]:
        async with self._lock:
            await self._close_unlocked(reset_state=True)
        return self.snapshot()

    async def _close_unlocked(self, *, reset_state: bool) -> None:
        if self._login_task and not self._login_task.done():
            self._login_task.cancel()
            try:
                await self._login_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        self._login_task = None

        if self._client is not None:
            try:
                await self._client.close()
            except Exception:
                logger.exception("[WEB] 关闭客户端失败")
        self._client = None
        self._plugin_manager = None

        if reset_state:
            last_blueprint_query = self._state.last_blueprint_query
            last_shop_price_state = self._state.last_shop_price_state
            self._state = SessionState(
                last_blueprint_query=last_blueprint_query,
                last_shop_price_state=last_shop_price_state,
            )
