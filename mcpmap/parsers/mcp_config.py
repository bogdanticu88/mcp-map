from __future__ import annotations

import re
from typing import Any

from mcpmap.parsers.base import BaseParser, ParsedAgent, ParsedServer, ParsedTool


_NPX_PKG_RE = re.compile(r"^(@[\w/-]+|[\w-]+(?:/[\w-]+)?)")


def _extract_package(args: list[str]) -> str:
    for arg in args:
        if arg.startswith("-"):
            continue
        m = _NPX_PKG_RE.match(arg)
        if m:
            return m.group(0)
    return ""


def _extract_tools(server_data: dict[str, Any]) -> list[ParsedTool]:
    tools: list[ParsedTool] = []
    for tool_entry in server_data.get("tools", []):
        if isinstance(tool_entry, dict):
            tools.append(ParsedTool(
                name=tool_entry.get("name", ""),
                description=tool_entry.get("description", ""),
                parameters=tool_entry.get("parameters", {}),
                source="inline",
            ))
    return tools


class MCPConfigParser(BaseParser):
    def can_parse(self, data: dict[str, Any], path: str) -> bool:
        return "mcpServers" in data or (
            isinstance(data.get("mcp"), dict) and "servers" in data["mcp"]
        )

    def parse(self, data: dict[str, Any], path: str) -> ParsedAgent:
        servers: list[ParsedServer] = []

        raw_servers: dict[str, Any] = {}
        if "mcpServers" in data:
            raw_servers = data["mcpServers"]
        elif isinstance(data.get("mcp"), dict):
            raw_servers = data["mcp"].get("servers", {})

        for name, cfg in raw_servers.items():
            if not isinstance(cfg, dict):
                continue

            url = cfg.get("url", "")
            is_remote = bool(url)
            command = "" if is_remote else cfg.get("command", "")
            args: list[str] = [] if is_remote else cfg.get("args", [])

            env: dict[str, str] = {k: str(v) for k, v in cfg.get("env", {}).items()}
            # Treat HTTP headers like env vars for secret-detection rules
            for k, v in cfg.get("headers", {}).items():
                env[f"HEADER_{k.upper().replace('-', '_')}"] = str(v)

            package = ""
            if is_remote:
                from urllib.parse import urlparse
                package = urlparse(url).netloc or url
            elif command in ("npx", "uvx", "bunx", "node"):
                package = _extract_package(args)
            elif command:
                package = command

            servers.append(ParsedServer(
                name=name,
                command=command,
                args=args,
                env=env,
                package=package,
                tools=_extract_tools(cfg),
                is_remote=is_remote,
                url=url,
            ))

        return ParsedAgent(source_path=path, format="mcp-config", servers=servers)
