import argparse
import asyncio
import json
import logging
import shlex
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from config.get_config import EndfieldConfigFetcher
from login.passport_login import PassportLogin, PassportLoginResult
from login.u8_login import U8Login, U8LoginResult
from plugins import BlueprintQueryPlugin, PluginManager, ShopPriceQueryPlugin
from tcp.srsa_bridge import SRSABridge
from tcp.tcp import (
    DEFAULT_FIRST_HEARTBEAT_DELAY_MS,
    DEFAULT_FIRST_HEARTBEAT_IDLE_WINDOW_MS,
    DEFAULT_HEARTBEAT_INTERVAL_MS,
    DEFAULT_LOGICAL_TS_STRATEGY,
    DEFAULT_SESSION_DECRYPT_COUNTER,
    DEFAULT_SESSION_ENCRYPT_COUNTER,
    LOGICAL_TS_STRATEGIES,
    TCPClient,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

try:
    from prompt_toolkit.application import Application
    from prompt_toolkit.document import Document
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.layout import Layout
    from prompt_toolkit.layout.containers import HSplit, VSplit
    from prompt_toolkit.styles import Style
    from prompt_toolkit.widgets import Frame, TextArea

    PROMPT_TOOLKIT_AVAILABLE = True
    PROMPT_TOOLKIT_IMPORT_ERROR: Optional[Exception] = None
except Exception as exc:
    PROMPT_TOOLKIT_AVAILABLE = False
    PROMPT_TOOLKIT_IMPORT_ERROR = exc


class CLIArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)

    def exit(self, status: int = 0, message: Optional[str] = None) -> None:
        if message:
            raise ValueError(message)
        raise ValueError(f"命令退出，status={status}")


class EndfieldClient:
    def __init__(
        self,
        dll_dir: Path,
        config_dir: Optional[Path] = None,
        is_oversea: bool = False,
        qrcode_dir: Optional[Path] = None,
        tcp_options: Optional[dict[str, Any]] = None,
    ):
        self.dll_dir = dll_dir
        self.config_dir = config_dir
        self.is_oversea = is_oversea
        self.qrcode_dir = qrcode_dir
        self.tcp_options = dict(tcp_options or {})

        self._config: Optional[dict[str, Any]] = None
        self._passport_result: Optional[PassportLoginResult] = None
        self._u8_result: Optional[U8LoginResult] = None
        self._srsa_bridge: Optional[SRSABridge] = None
        self._tcp_client: Optional[TCPClient] = None
        self._passport_login_driver: Optional[PassportLogin] = None
        self._plugin_manager: Optional[PluginManager] = None
        self._selected_server: Optional[dict[str, Any]] = None
        self._selected_host: str = ""
        self._selected_port: int = 0
        self._login_response: Optional[Any] = None

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
        self._passport_login_driver = login
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

    def set_selected_server(self, server: dict[str, Any], host: str, port: int) -> None:
        self._selected_server = dict(server)
        self._selected_host = str(host or "")
        self._selected_port = int(port or 0)

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
        self._tcp_client = TCPClient(self.dll_dir, **self.tcp_options)

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
        self.init_plugins()
        await self._tcp_client.start_session()
        self._login_response = login_response
        logger.info("[TCP] 长连接保持已启动")

        return login_response

    def init_plugins(self) -> PluginManager:
        """初始化实验性 plugin 管理器"""
        if not self._tcp_client:
            raise RuntimeError("TCP 会话尚未建立，无法初始化 plugin")

        if self._plugin_manager is None:
            manager = PluginManager(self._tcp_client)
            manager.register(BlueprintQueryPlugin(self._tcp_client))
            manager.register(ShopPriceQueryPlugin(self._tcp_client))
            self._plugin_manager = manager
            logger.info("[Plugin] 已注册插件：%s", ", ".join(self._plugin_manager.names()))

        return self._plugin_manager

    async def query_shared_blueprint(self, share_code: str, *, timeout: float = 10.0) -> dict[str, Any]:
        """执行蓝图查询 plugin"""
        manager = self.init_plugins()
        plugin = manager.get("blueprint-query")
        if not isinstance(plugin, BlueprintQueryPlugin):
            raise RuntimeError("blueprint-query plugin 未初始化")
        return await plugin.query_shared_blueprint(share_code, timeout=timeout)

    def get_status_snapshot(self) -> dict[str, Any]:
        server = self._selected_server or {}
        tcp_connected = bool(self._tcp_client and self._tcp_client.writer is not None)
        session_started = bool(self._tcp_client and self._tcp_client._session_started)
        session_closed = bool(
            self._tcp_client
            and self._tcp_client._closed_event is not None
            and self._tcp_client._closed_event.is_set()
        )
        return {
            "config_loaded": self._config is not None,
            "passport_logged_in": self._passport_result is not None,
            "u8_logged_in": self._u8_result is not None,
            "tcp_connected": tcp_connected,
            "session_started": session_started,
            "session_closed": session_closed,
            "uid": self._u8_result.uid if self._u8_result else "",
            "login_uid": self._login_response.uid if self._login_response else "",
            "server_id": str(server.get("serverId") or ""),
            "server_name": str(server.get("serverName") or ""),
            "host": self._selected_host,
            "port": self._selected_port,
            "qrcode_path": getattr(self._passport_login_driver, "last_qrcode_path", None),
            "scan_url": getattr(self._passport_login_driver, "last_scan_url", None),
            "plugins": self._plugin_manager.names() if self._plugin_manager else [],
        }

    async def wait_forever(self) -> None:
        if not self._tcp_client:
            raise RuntimeError("TCP 会话尚未建立")
        await self._tcp_client.wait_forever()

    async def close(self) -> None:
        if self._tcp_client:
            await self._tcp_client.close()
            self._tcp_client = None
        self._plugin_manager = None
        self._login_response = None


def _render_blueprint_query_result(result: dict[str, Any], output_mode: str) -> str:
    blueprint_data = result.get("blueprint_data") or {}
    bp_size = blueprint_data.get("bp_size") or {}
    summary_lines = [
        "[Plugin blueprint-query] 查询成功",
        f"  share_code: {result.get('share_code', '')}",
        f"  request_index: {result.get('request_index', '')}",
        f"  response_index: {result.get('response_index', '')}",
        f"  name: {blueprint_data.get('name', '')}",
        f"  review_status: {blueprint_data.get('review_status_name', '')}",
        f"  size: {bp_size.get('x_len', 0)} x {bp_size.get('z_len', 0)}",
        f"  node_count: {blueprint_data.get('node_count', 0)}",
        f"  component_count: {blueprint_data.get('component_count', 0)}",
        f"  creator_user_id: {blueprint_data.get('creator_user_id', '')}",
    ]

    sections: list[str] = []
    if output_mode in {"summary", "both"}:
        sections.append("\n".join(summary_lines))

    if output_mode in {"json", "both"}:
        sections.append(json.dumps(result, ensure_ascii=False, indent=2))

    return "\n\n".join(section for section in sections if section)


def _print_blueprint_query_result(result: dict[str, Any], output_mode: str) -> None:
    rendered = _render_blueprint_query_result(result, output_mode)
    if rendered:
        print(rendered)


@dataclass
class CLICommandResult:
    output: str = ""
    exit_requested: bool = False
    clear_output: bool = False
    clear_logs: bool = False
    toggle_ping_filter: bool = False


class CLICommandProcessor:
    def __init__(self, client: EndfieldClient):
        self.client = client

    async def execute_line(self, line: str) -> CLICommandResult:
        parts = shlex.split(line)
        if not parts:
            return CLICommandResult()

        command = parts[0].lower()
        args = parts[1:]

        if command in {"help", "h", "?"}:
            return CLICommandResult(output=self.help_text())
        if command == "status":
            return CLICommandResult(output=self.status_text())
        if command == "plugins":
            return CLICommandResult(output=self.plugins_text())
        if command == "clear":
            return CLICommandResult(clear_output=True)
        if command in {"clear-log", "clear-logs"}:
            return CLICommandResult(clear_logs=True)
        if command in {"toggle-ping-log", "toggle-ping", "toggle-heartbeat-log"}:
            return CLICommandResult(toggle_ping_filter=True)
        if command in {"blueprint-query", "bq"}:
            return CLICommandResult(output=await self._command_blueprint_query(args))
        if command in {"exit", "quit"}:
            return CLICommandResult(output="准备退出交互界面。", exit_requested=True)

        raise ValueError(f"未知命令: {command}，输入 help 查看可用命令")

    def help_text(self) -> str:
        return "\n".join(
            [
                "可用命令：",
                "  help",
                "    显示帮助",
                "  status",
                "    显示当前登录/会话状态",
                "  plugins",
                "    显示当前已注册的 plugin",
                "  blueprint-query <share_code> [--timeout 秒] [--output summary|json|both]",
                "    查询蓝图分享码",
                "  clear",
                "    清空结果面板",
                "  clear-logs",
                "    清空日志面板",
                "  toggle-ping-log",
                "    切换是否过滤高频心跳日志",
                "  exit | quit",
                "    退出程序",
            ]
        )

    def short_help_text(self) -> str:
        return "\n".join(
            [
                "help",
                "status",
                "plugins",
                "blueprint-query <share_code>",
                "clear",
                "clear-logs",
                "toggle-ping-log",
                "exit",
            ]
        )

    def status_text(self) -> str:
        snapshot = self.client.get_status_snapshot()
        lines = [
            "当前状态：",
            f"  config_loaded: {snapshot.get('config_loaded')}",
            f"  passport_logged_in: {snapshot.get('passport_logged_in')}",
            f"  u8_logged_in: {snapshot.get('u8_logged_in')}",
            f"  tcp_connected: {snapshot.get('tcp_connected')}",
            f"  session_started: {snapshot.get('session_started')}",
            f"  session_closed: {snapshot.get('session_closed')}",
            f"  uid: {snapshot.get('uid') or snapshot.get('login_uid') or '-'}",
            f"  server: {snapshot.get('server_name') or '-'} ({snapshot.get('server_id') or '-'})",
            f"  host_port: {snapshot.get('host') or '-'}:{snapshot.get('port') or '-'}",
            f"  plugins: {', '.join(snapshot.get('plugins') or []) or '-'}",
        ]

        qrcode_path = snapshot.get("qrcode_path")
        if qrcode_path:
            lines.append(f"  qrcode_path: {qrcode_path}")
        scan_url = snapshot.get("scan_url")
        if scan_url:
            lines.append(f"  scan_url: {scan_url}")

        return "\n".join(lines)

    def plugins_text(self) -> str:
        plugins = self.client.get_status_snapshot().get("plugins") or []
        if not plugins:
            return "当前没有可用 plugin。"
        return "已注册 plugin：\n" + "\n".join(f"  - {name}" for name in plugins)

    async def _command_blueprint_query(self, argv: list[str]) -> str:
        if not argv or any(item in {"-h", "--help"} for item in argv):
            return "用法: blueprint-query <share_code> [--timeout 秒] [--output summary|json|both]"

        parser = CLIArgumentParser(
            prog="blueprint-query",
            add_help=False,
            description="查询蓝图分享码",
        )
        parser.add_argument("share_code")
        parser.add_argument("--timeout", type=float, default=10.0)
        parser.add_argument("--output", choices=["summary", "json", "both"], default="both")
        parsed = parser.parse_args(argv)
        if parsed.timeout <= 0:
            raise ValueError("--timeout 必须大于 0")

        result = await self.client.query_shared_blueprint(
            parsed.share_code,
            timeout=float(parsed.timeout),
        )
        return _render_blueprint_query_result(result, parsed.output)


class InteractiveCLI:
    def __init__(self, client: EndfieldClient, initial_output: str = ""):
        self.client = client
        self._running = True
        self._processor = CLICommandProcessor(client)
        self._initial_output = initial_output

    def _prompt(self) -> str:
        snapshot = self.client.get_status_snapshot()
        uid = snapshot.get("uid") or snapshot.get("login_uid") or "unknown"
        return f"endfield:{uid}> "

    async def run(self) -> None:
        print("简易 CLI 已启动。输入 help 查看命令，输入 exit 退出。")
        if self._initial_output:
            print(self._initial_output)
        while self._running:
            try:
                line = await asyncio.to_thread(input, self._prompt())
            except EOFError:
                print("收到 EOF，准备退出。")
                return
            except KeyboardInterrupt:
                print("\n收到中断，准备退出。")
                return

            line = line.strip()
            if not line:
                continue

            try:
                result = await self._processor.execute_line(line)
            except Exception as exc:
                print(f"[CLI] 命令执行失败: {exc}")
                continue

            if result.clear_output:
                print("\033[2J\033[H", end="")
            if result.clear_logs:
                print("[CLI] 当前为简易 CLI，没有独立日志面板可清空。")
            if result.toggle_ping_filter:
                print("[CLI] 当前为简易 CLI，没有 TUI 日志过滤开关。")
            if result.output:
                print(result.output)
            if result.exit_requested:
                self._running = False


if PROMPT_TOOLKIT_AVAILABLE:
    class TUILogHandler(logging.Handler):
        def __init__(self, invalidate_callback, *, max_lines: int = 400):
            super().__init__()
            self._invalidate_callback = invalidate_callback
            self._lines: deque[str] = deque(maxlen=max_lines)
            self.filter_ping_noise = True
            self.hidden_ping_logs = 0

        @staticmethod
        def _is_ping_noise(message: str) -> bool:
            ping_tokens = (
                "已发送 CsPing",
                "收到 ScPing",
                "已发送 CsFlushSync",
                "收到 ScFlushSync",
                "已发送 CsSyncLogicalTs",
            )
            if any(token in message for token in ping_tokens):
                return True
            if "收到服务端消息:" in message and ("msgid=5" in message or "msgid=8" in message):
                return True
            return False

        def emit(self, record: logging.LogRecord) -> None:
            try:
                message = self.format(record)
            except Exception:
                message = record.getMessage()

            if self.filter_ping_noise and self._is_ping_noise(message):
                self.hidden_ping_logs += 1
                return

            self._lines.append(message)
            if self._invalidate_callback is not None:
                try:
                    self._invalidate_callback()
                except Exception:
                    pass

        def render_text(self) -> str:
            if not self._lines:
                return "暂无日志。"
            return "\n".join(self._lines)

        def clear(self) -> None:
            self._lines.clear()
            self.hidden_ping_logs = 0
            if self._invalidate_callback is not None:
                try:
                    self._invalidate_callback()
                except Exception:
                    pass


    class InteractiveTUI:
        def __init__(self, client: EndfieldClient, initial_output: str = ""):
            self.client = client
            self._processor = CLICommandProcessor(client)
            self._running = True
            self._output_blocks: deque[str] = deque(maxlen=40)
            self._initial_output = initial_output
            self._saved_root_handlers: list[logging.Handler] = []
            self._saved_root_level: int = logging.INFO
            self._refresh_task: Optional[asyncio.Task[None]] = None

            self.header_area = TextArea(
                text="初始化中...",
                read_only=True,
                focusable=False,
                scrollbar=False,
                height=2,
                style="class:header",
            )
            self.status_area = TextArea(
                text="",
                read_only=True,
                focusable=False,
                scrollbar=True,
                style="class:status",
            )
            self.help_area = TextArea(
                text=self._processor.short_help_text(),
                read_only=True,
                focusable=False,
                scrollbar=False,
                style="class:help",
            )
            self.output_area = TextArea(
                text="",
                read_only=True,
                focusable=False,
                scrollbar=True,
                style="class:output",
            )
            self.log_area = TextArea(
                text="",
                read_only=True,
                focusable=False,
                scrollbar=True,
                style="class:logs",
            )
            self.input_area = TextArea(
                height=1,
                prompt="cmd> ",
                multiline=False,
                wrap_lines=False,
                style="class:input",
                accept_handler=self._accept_handler,
            )

            self._log_handler = TUILogHandler(self._request_invalidate)
            self._log_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

            body = HSplit(
                [
                    Frame(self.header_area, title="会话概览"),
                    VSplit(
                        [
                            HSplit(
                                [
                                    Frame(self.status_area, title="状态"),
                                    Frame(self.help_area, title="命令速查"),
                                ],
                                width=44,
                            ),
                            HSplit(
                                [
                                    Frame(self.output_area, title="结果"),
                                    Frame(self.log_area, title="日志"),
                                ]
                            ),
                        ]
                    ),
                    Frame(self.input_area, title="命令输入"),
                ]
            )

            bindings = KeyBindings()

            @bindings.add("c-c")
            @bindings.add("c-q")
            def _exit(event) -> None:
                self._running = False
                event.app.exit()

            @bindings.add("f5")
            def _refresh(_event) -> None:
                self._update_views()

            self.application = Application(
                layout=Layout(body, focused_element=self.input_area),
                key_bindings=bindings,
                full_screen=True,
                mouse_support=True,
                style=Style.from_dict(
                    {
                        "header": "bg:#5b3d1d #f6f0e8",
                        "status": "bg:#1f2430 #d8dee9",
                        "help": "bg:#23303b #b7c5d3",
                        "output": "bg:#18212b #f1f5f9",
                        "logs": "bg:#111827 #cbd5e1",
                        "input": "bg:#0f172a #f8fafc",
                        "frame.border": "#c07432",
                        "frame.label": "bold",
                    }
                ),
            )

        def _request_invalidate(self) -> None:
            if hasattr(self, "application"):
                try:
                    self.application.invalidate()
                except Exception:
                    pass

        def _install_logging_capture(self) -> None:
            root_logger = logging.getLogger()
            self._saved_root_handlers = list(root_logger.handlers)
            self._saved_root_level = root_logger.level
            root_logger.handlers = [self._log_handler]
            root_logger.setLevel(logging.INFO)

        def _restore_logging_capture(self) -> None:
            root_logger = logging.getLogger()
            root_logger.handlers = self._saved_root_handlers
            root_logger.setLevel(self._saved_root_level)

        def _append_output(self, text: str) -> None:
            if not text:
                return
            normalized = text.rstrip()
            if not normalized:
                return
            self._output_blocks.append(normalized)
            self._update_views()

        def _set_textarea_text(self, area: TextArea, text: str, *, follow_end: bool = False) -> None:
            if area.text == text:
                return

            buffer = area.buffer
            old_cursor = buffer.cursor_position
            old_vertical_scroll = getattr(area.window, "vertical_scroll", 0)
            render_info = getattr(area.window, "render_info", None)
            was_bottom_visible = bool(render_info.bottom_visible) if render_info is not None else old_cursor >= len(buffer.text)

            if follow_end and was_bottom_visible:
                new_cursor = len(text)
            else:
                new_cursor = min(old_cursor, len(text))

            area.document = Document(text, new_cursor)

            if not (follow_end and was_bottom_visible):
                try:
                    area.window.vertical_scroll = old_vertical_scroll
                except Exception:
                    pass

        def _build_header_text(self) -> str:
            snapshot = self.client.get_status_snapshot()
            uid = snapshot.get("uid") or snapshot.get("login_uid") or "-"
            server_name = snapshot.get("server_name") or "-"
            host = snapshot.get("host") or "-"
            port = snapshot.get("port") or "-"
            ping_filter_state = "ON" if self._log_handler.filter_ping_noise else "OFF"
            return (
                f"UID: {uid}    Server: {server_name}    TCP: {host}:{port}\n"
                f"Plugins: {', '.join(snapshot.get('plugins') or []) or '-'}    "
                f"Ping filter: {ping_filter_state}    Hidden: {self._log_handler.hidden_ping_logs}    Ctrl-C/Ctrl-Q 退出"
            )

        def _update_views(self) -> None:
            self._set_textarea_text(self.header_area, self._build_header_text())
            self._set_textarea_text(self.status_area, self._processor.status_text())
            self._set_textarea_text(self.help_area, self._processor.short_help_text())
            self._set_textarea_text(
                self.output_area,
                "\n\n".join(self._output_blocks) if self._output_blocks else "命令输出会显示在这里。输入 help 查看可用命令。",
                follow_end=True,
            )
            self._set_textarea_text(self.log_area, self._log_handler.render_text(), follow_end=True)
            self._request_invalidate()

        def _accept_handler(self, buffer) -> bool:
            line = buffer.text.strip()
            buffer.text = ""
            if line:
                asyncio.create_task(self._handle_command(line))
            return False

        async def _handle_command(self, line: str) -> None:
            self._append_output(f"> {line}")
            try:
                result = await self._processor.execute_line(line)
            except Exception as exc:
                self._append_output(f"[CLI] 命令执行失败: {exc}")
                return

            if result.clear_output:
                self._output_blocks.clear()
            if result.clear_logs:
                self._log_handler.clear()
                self._append_output("[TUI] 日志面板已清空。")
            if result.toggle_ping_filter:
                self._log_handler.filter_ping_noise = not self._log_handler.filter_ping_noise
                state_text = "开启" if self._log_handler.filter_ping_noise else "关闭"
                self._append_output(f"[TUI] 心跳日志过滤已{state_text}。")
            if result.output:
                self._append_output(result.output)
            if result.exit_requested:
                self._running = False
                self.application.exit()

        async def _refresh_loop(self) -> None:
            try:
                while self._running:
                    self._update_views()
                    await asyncio.sleep(0.25)
            except asyncio.CancelledError:
                raise

        async def run(self) -> None:
            self._append_output("交互式 TUI 已启动。日志显示在右下角，命令结果显示在右上角。")
            self._append_output("默认已过滤高频心跳日志，可用 toggle-ping-log 切换。")
            self._append_output("输入 help 查看命令。")
            if self._initial_output:
                self._append_output(self._initial_output)
            self._install_logging_capture()
            self._update_views()
            self._refresh_task = asyncio.create_task(self._refresh_loop())
            try:
                await self.application.run_async()
            finally:
                if self._refresh_task is not None:
                    self._refresh_task.cancel()
                    try:
                        await self._refresh_task
                    except asyncio.CancelledError:
                        pass
                self._restore_logging_capture()


else:
    class InteractiveTUI:
        def __init__(self, _client: EndfieldClient, initial_output: str = ""):
            raise RuntimeError(f"prompt_toolkit 不可用: {PROMPT_TOOLKIT_IMPORT_ERROR}")


async def run_interactive_session(client: EndfieldClient, *, initial_output: str = "") -> None:
    if PROMPT_TOOLKIT_AVAILABLE:
        session = InteractiveTUI(client, initial_output=initial_output)
    else:
        logger.warning("prompt_toolkit 不可用，回退到简易 CLI: %s", PROMPT_TOOLKIT_IMPORT_ERROR)
        session = InteractiveCLI(client, initial_output=initial_output)
    await session.run()


async def main():
    parser = argparse.ArgumentParser(description="Endfield 无头客户端")
    parser.add_argument("--dll-dir", type=Path, required=True, help="GameAssembly.dll 所在目录")
    parser.add_argument("--config-dir", type=Path, default=Path(__file__).parent / "Data" / "tmp", help="配置保存目录")
    parser.add_argument("--skip-config", action="store_true", help="跳过配置获取")
    parser.add_argument("--oversea", action="store_true", help="使用海外服务器")
    parser.add_argument("--server-id", type=str, help="指定服务器 ID")
    parser.add_argument("--qrcode-dir", type=Path, help="二维码图片保存目录 (默认：./qrcode)")
    parser.add_argument("--tcp-send-counter", type=int, default=DEFAULT_SESSION_ENCRYPT_COUNTER, help="会话上行 XXE1 初始 counter")
    parser.add_argument("--tcp-recv-counter", type=int, default=DEFAULT_SESSION_DECRYPT_COUNTER, help="会话下行 XXE1 初始 counter")
    parser.add_argument("--tcp-ping-interval-ms", type=int, default=DEFAULT_HEARTBEAT_INTERVAL_MS, help="CsPing 发送间隔")
    parser.add_argument("--tcp-first-ping-delay-ms", type=int, default=DEFAULT_FIRST_HEARTBEAT_DELAY_MS, help="登录后首个心跳延迟")
    parser.add_argument("--tcp-first-ping-idle-window-ms", type=int, default=DEFAULT_FIRST_HEARTBEAT_IDLE_WINDOW_MS, help="登录后等待服务端静默多久再发首个心跳")
    parser.add_argument("--tcp-logical-ts-strategy", type=str, choices=sorted(LOGICAL_TS_STRATEGIES), default=DEFAULT_LOGICAL_TS_STRATEGY, help="CsPing/CsSyncLogicalTs 的 logicalTs 取值策略")
    parser.add_argument("--plugin", type=str, choices=["blueprint-query"], help="登录后执行指定 plugin")
    parser.add_argument("--share-code", type=str, help="blueprint-query 使用的蓝图分享码")
    parser.add_argument("--plugin-timeout", type=float, default=10.0, help="plugin 请求超时（秒）")
    parser.add_argument("--plugin-output", type=str, choices=["summary", "json", "both"], default="both", help="plugin 输出格式")
    parser.add_argument("--wait-after-plugin", action="store_true", help="plugin 执行完成后继续保持长连接")
    parser.add_argument("--no-cli", action="store_true", help="登录成功后不进入交互式 TUI，沿用旧的纯日志模式")

    args = parser.parse_args()

    if args.plugin == "blueprint-query" and not args.share_code:
        parser.error("--plugin blueprint-query 时必须提供 --share-code")
    if args.share_code and args.plugin != "blueprint-query":
        parser.error("--share-code 需要配合 --plugin blueprint-query 使用")
    if args.wait_after_plugin and not args.plugin:
        parser.error("--wait-after-plugin 需要配合 --plugin 使用")
    if args.plugin_timeout <= 0:
        parser.error("--plugin-timeout 必须大于 0")

    # 默认二维码保存目录
    if args.qrcode_dir is None:
        args.qrcode_dir = Path(__file__).parent / "qrcode"

    tcp_options = {
        "session_encrypt_counter": args.tcp_send_counter,
        "session_decrypt_counter": args.tcp_recv_counter,
        "heartbeat_interval_ms": args.tcp_ping_interval_ms,
        "first_ping_delay_ms": args.tcp_first_ping_delay_ms,
        "first_ping_idle_window_ms": args.tcp_first_ping_idle_window_ms,
        "logical_ts_strategy": args.tcp_logical_ts_strategy,
    }

    client = EndfieldClient(
        dll_dir=args.dll_dir,
        config_dir=args.config_dir,
        is_oversea=args.oversea,
        qrcode_dir=args.qrcode_dir,
        tcp_options=tcp_options,
    )

    try:
        if not args.skip_config:
            await client.fetch_config()
        else:
            logger.info("[Config] 跳过配置获取")

        await client.passport_login()
        await client.u8_login(client._passport_result.channel_token)

        server = client.get_server(args.server_id)
        logger.info(f"[Server] 选择服务器：{server.get('serverName')}")

        host_port = json.loads(server.get("serverDomain", "[]"))
        if not host_port:
            raise RuntimeError("未获取到服务器地址")

        host = host_port[0].get("host")
        port = host_port[0].get("port")
        logger.info(f"[TCP] 服务器地址：{host}:{port}")
        client.set_selected_server(server, host, int(port))

        client.init_srsa()

        login_response = await client.tcp_login(
            host=host,
            port=port,
            uid=client._u8_result.uid,
            grant_code=client._u8_result.grant_code
        )

        logger.info(f"[Client] 登录流程完成，uid={login_response.uid}")

        if args.plugin == "blueprint-query":
            result = await client.query_shared_blueprint(
                args.share_code,
                timeout=float(args.plugin_timeout),
            )
            plugin_rendered_output = _render_blueprint_query_result(result, args.plugin_output)
            if args.no_cli:
                print(plugin_rendered_output)

            if args.no_cli and args.wait_after_plugin:
                logger.info("[Client] plugin 执行完成，长连接保持中，按 Ctrl+C 退出")
                await client.wait_forever()
            elif args.no_cli:
                logger.info("[Client] plugin 执行完成，准备退出")
            else:
                await run_interactive_session(client, initial_output=plugin_rendered_output)
        elif args.no_cli:
            logger.info("[Client] 长连接保持中，按 Ctrl+C 退出")
            await client.wait_forever()
        else:
            await run_interactive_session(client)
    finally:
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
