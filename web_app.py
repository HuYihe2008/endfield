from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from tcp.tcp import (
    DEFAULT_FIRST_HEARTBEAT_DELAY_MS,
    DEFAULT_FIRST_HEARTBEAT_IDLE_WINDOW_MS,
    DEFAULT_HEARTBEAT_INTERVAL_MS,
    DEFAULT_LOGICAL_TS_STRATEGY,
    DEFAULT_SESSION_DECRYPT_COUNTER,
    DEFAULT_SESSION_ENCRYPT_COUNTER,
)
from web.session_manager import EndfieldSessionManager


class LoginRequest(BaseModel):
    skip_config: bool = False
    oversea: bool = False
    server_id: Optional[str] = None


class BlueprintQueryRequest(BaseModel):
    share_code: str = Field(..., min_length=1)
    timeout: float = Field(default=10.0, ge=1.0, le=60.0)


class DomainDevelopmentReadVersionRequest(BaseModel):
    chapter_id: Optional[str] = None
    timeout: float = Field(default=10.0, ge=1.0, le=60.0)


class ShopBeginRequest(BaseModel):
    domain_id: Optional[str] = None
    timeout: float = Field(default=10.0, ge=1.0, le=60.0)


class ObserveInboundRequest(BaseModel):
    timeout: float = Field(default=10.0, ge=1.0, le=60.0)


class ObserveMessagesRequest(BaseModel):
    timeout: float = Field(default=10.0, ge=1.0, le=60.0)
    msgid: Optional[int] = Field(default=None, ge=1)


class DomainSwitchRequest(BaseModel):
    domain_id: str = Field(..., min_length=1)
    timeout: float = Field(default=10.0, ge=1.0, le=60.0)


class ShopFriendGoodsPriceRequest(BaseModel):
    shop_id: str = Field(..., min_length=1)
    goods_id: str = Field(..., min_length=1)
    role_ids: list[int] = Field(default_factory=list)
    timeout: float = Field(default=10.0, ge=1.0, le=60.0)


class ShopFriendShopRequest(BaseModel):
    friend_role_id: int = Field(..., ge=1)
    shop_ids: list[str] = Field(default_factory=list)
    timeout: float = Field(default=10.0, ge=1.0, le=60.0)


class DomainShopBindingRequest(BaseModel):
    domain_id: str = Field(..., min_length=1)
    shop_id: str = Field(..., min_length=1)
    channel_id: Optional[str] = None
    preferred: bool = True
    note: Optional[str] = None


def create_app(session_manager: EndfieldSessionManager) -> FastAPI:
    app = FastAPI(title="Endfield Experimental WebUI", version="0.1.0")

    web_dir = Path(__file__).resolve().parent / "web"
    qrcode_dir = session_manager.qrcode_dir

    app.mount("/qrcode", StaticFiles(directory=str(qrcode_dir)), name="qrcode")

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(web_dir / "index.html")

    @app.get("/api/session")
    async def get_session() -> dict[str, object]:
        return session_manager.snapshot()

    @app.post("/api/session/login")
    async def start_login(payload: LoginRequest) -> dict[str, object]:
        try:
            return await session_manager.start_login(
                skip_config=payload.skip_config,
                oversea=payload.oversea,
                server_id=payload.server_id,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/session/close")
    async def close_session() -> dict[str, object]:
        try:
            return await session_manager.close()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/plugins")
    async def list_plugins() -> dict[str, object]:
        state = session_manager.snapshot()
        return {"plugins": state.get("available_plugins", [])}

    @app.post("/api/plugins/blueprint-query")
    async def query_blueprint(payload: BlueprintQueryRequest) -> dict[str, object]:
        try:
            return await session_manager.query_shared_blueprint(
                payload.share_code,
                timeout=payload.timeout,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/plugins/shop-price-query/state")
    async def get_shop_price_state() -> dict[str, object]:
        try:
            return await session_manager.get_shop_price_state()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/plugins/shop-price-query/domainshops")
    async def get_shop_price_domainshops() -> dict[str, object]:
        try:
            return await session_manager.get_shop_price_domainshops()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/plugins/shop-price-query/domain-development/read-version")
    async def read_domain_development_version(
        payload: DomainDevelopmentReadVersionRequest,
    ) -> dict[str, object]:
        try:
            return await session_manager.read_domain_development_versions(
                payload.chapter_id,
                timeout=payload.timeout,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/plugins/shop-price-query/domain-development/observe")
    async def observe_domain_development(
        payload: ObserveInboundRequest,
    ) -> dict[str, object]:
        try:
            return await session_manager.observe_domain_development(timeout=payload.timeout)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/plugins/shop-price-query/domain/switch")
    async def switch_domain(payload: DomainSwitchRequest) -> dict[str, object]:
        try:
            return await session_manager.change_current_domain(
                payload.domain_id,
                timeout=payload.timeout,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/plugins/shop-price-query/shop-begin")
    async def shop_begin(payload: ShopBeginRequest) -> dict[str, object]:
        try:
            return await session_manager.enter_shop(
                payload.domain_id,
                timeout=payload.timeout,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/plugins/shop-price-query/shop/observe")
    async def observe_shop(payload: ObserveInboundRequest) -> dict[str, object]:
        try:
            return await session_manager.observe_shop_sync(timeout=payload.timeout)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/plugins/shop-price-query/messages/observe")
    async def observe_messages(payload: ObserveMessagesRequest) -> dict[str, object]:
        try:
            return await session_manager.observe_inbound_messages(
                timeout=payload.timeout,
                msgid=payload.msgid,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/plugins/shop-price-query/friend-goods-price")
    async def query_friend_goods_price(
        payload: ShopFriendGoodsPriceRequest,
    ) -> dict[str, object]:
        try:
            return await session_manager.query_friend_goods_price(
                payload.shop_id,
                payload.goods_id,
                payload.role_ids,
                timeout=payload.timeout,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/plugins/shop-price-query/friend-shop")
    async def query_friend_shop(payload: ShopFriendShopRequest) -> dict[str, object]:
        try:
            return await session_manager.query_friend_shop(
                payload.friend_role_id,
                payload.shop_ids,
                timeout=payload.timeout,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/plugins/shop-price-query/domain-binding")
    async def bind_domain_shop(payload: DomainShopBindingRequest) -> dict[str, object]:
        try:
            return await session_manager.update_domain_shop_binding(
                payload.domain_id,
                payload.shop_id,
                channel_id=payload.channel_id,
                preferred=payload.preferred,
                note=payload.note,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Endfield 实验性 WebUI")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址")
    parser.add_argument("--port", type=int, default=18080, help="监听端口")
    parser.add_argument("--dll-dir", type=Path, required=True, help="GameAssembly.dll 所在目录")
    parser.add_argument("--config-dir", type=Path, default=Path(__file__).parent / "Data" / "tmp", help="配置保存目录")
    parser.add_argument("--qrcode-dir", type=Path, default=Path(__file__).parent / "qrcode", help="二维码保存目录")
    parser.add_argument("--tcp-send-counter", type=int, default=DEFAULT_SESSION_ENCRYPT_COUNTER, help="会话上行 XXE1 初始 counter")
    parser.add_argument("--tcp-recv-counter", type=int, default=DEFAULT_SESSION_DECRYPT_COUNTER, help="会话下行 XXE1 初始 counter")
    parser.add_argument("--tcp-ping-interval-ms", type=int, default=DEFAULT_HEARTBEAT_INTERVAL_MS, help="CsPing 发送间隔")
    parser.add_argument("--tcp-first-ping-delay-ms", type=int, default=DEFAULT_FIRST_HEARTBEAT_DELAY_MS, help="登录后首个心跳延迟")
    parser.add_argument("--tcp-first-ping-idle-window-ms", type=int, default=DEFAULT_FIRST_HEARTBEAT_IDLE_WINDOW_MS, help="登录后等待服务端静默多久再发首个心跳")
    parser.add_argument("--tcp-logical-ts-strategy", type=str, default=DEFAULT_LOGICAL_TS_STRATEGY, help="CsPing/CsSyncLogicalTs 的 logicalTs 取值策略")
    args = parser.parse_args()

    tcp_options = {
        "session_encrypt_counter": args.tcp_send_counter,
        "session_decrypt_counter": args.tcp_recv_counter,
        "heartbeat_interval_ms": args.tcp_ping_interval_ms,
        "first_ping_delay_ms": args.tcp_first_ping_delay_ms,
        "first_ping_idle_window_ms": args.tcp_first_ping_idle_window_ms,
        "logical_ts_strategy": args.tcp_logical_ts_strategy,
    }

    session_manager = EndfieldSessionManager(
        dll_dir=args.dll_dir,
        config_dir=args.config_dir,
        qrcode_dir=args.qrcode_dir,
        tcp_options=tcp_options,
    )
    app = create_app(session_manager)

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
