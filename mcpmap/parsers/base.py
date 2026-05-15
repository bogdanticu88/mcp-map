from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel, Field


class ParsedTool(BaseModel):
    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    source: str = ""


class ParsedServer(BaseModel):
    name: str
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    package: str = ""
    tools: list[ParsedTool] = Field(default_factory=list)
    is_remote: bool = False
    url: str = ""


class ParsedAgent(BaseModel):
    source_path: str
    format: str
    servers: list[ParsedServer] = Field(default_factory=list)


class BaseParser(ABC):
    @abstractmethod
    def can_parse(self, data: dict[str, Any], path: str) -> bool: ...

    @abstractmethod
    def parse(self, data: dict[str, Any], path: str) -> ParsedAgent: ...
