from __future__ import annotations

from typing import Any

from tcp.tcp import TCPClient


class PluginBase:
    name = "plugin"

    def __init__(self, tcp_client: TCPClient):
        self.tcp_client = tcp_client


class PluginManager:
    def __init__(self, tcp_client: TCPClient):
        self.tcp_client = tcp_client
        self._plugins: dict[str, PluginBase] = {}

    def register(self, plugin: PluginBase) -> PluginBase:
        self._plugins[plugin.name] = plugin
        return plugin

    def get(self, name: str) -> PluginBase:
        if name not in self._plugins:
            raise KeyError(f"未注册 plugin: {name}")
        return self._plugins[name]

    def names(self) -> list[str]:
        return sorted(self._plugins.keys())

    def describe(self) -> list[dict[str, Any]]:
        return [{"name": name} for name in self.names()]
