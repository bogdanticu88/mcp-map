from __future__ import annotations

from typing import Any

from mcpmap.parsers.base import BaseParser, ParsedAgent, ParsedServer, ParsedTool


class OpenAIToolsParser(BaseParser):
    def can_parse(self, data: dict[str, Any], path: str) -> bool:
        tools = data.get("tools", [])
        return isinstance(tools, list) and any(
            isinstance(t, dict) and t.get("type") == "function" for t in tools
        )

    def parse(self, data: dict[str, Any], path: str) -> ParsedAgent:
        tools: list[ParsedTool] = []
        for entry in data.get("tools", []):
            if not isinstance(entry, dict):
                continue
            func = entry.get("function", entry)
            name = func.get("name", "")
            description = func.get("description", "")
            parameters = func.get("parameters", {})
            tools.append(ParsedTool(
                name=name,
                description=description,
                parameters=parameters,
                source="openai-schema",
            ))

        synthetic_server = ParsedServer(name="__openai_tools__", tools=tools)
        return ParsedAgent(
            source_path=path,
            format="openai-tools",
            servers=[synthetic_server],
        )
