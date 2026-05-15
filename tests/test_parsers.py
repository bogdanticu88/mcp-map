import pytest
from mcpmap.parsers.mcp_config import MCPConfigParser
from mcpmap.parsers.openai_tools import OpenAIToolsParser


MCP_CONFIG = {
    "mcpServers": {
        "bash": {
            "command": "npx",
            "args": ["-y", "@anthropic-ai/mcp-server-bash"],
            "env": {"GITHUB_TOKEN": "ghp_test"},
        },
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
            "env": {},
        },
    }
}

OPENAI_TOOLS = {
    "tools": [
        {
            "type": "function",
            "function": {
                "name": "execute_command",
                "description": "Execute a shell command",
                "parameters": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                },
            },
        }
    ]
}


class TestMCPConfigParser:
    def setup_method(self):
        self.parser = MCPConfigParser()

    def test_can_parse_mcp_servers_key(self):
        assert self.parser.can_parse(MCP_CONFIG, "config.json")

    def test_cannot_parse_random_json(self):
        assert not self.parser.can_parse({"foo": "bar"}, "config.json")

    def test_parses_server_count(self):
        agent = self.parser.parse(MCP_CONFIG, "config.json")
        assert len(agent.servers) == 2

    def test_extracts_package(self):
        agent = self.parser.parse(MCP_CONFIG, "config.json")
        bash_server = next(s for s in agent.servers if s.name == "bash")
        assert "@anthropic-ai/mcp-server-bash" in bash_server.package

    def test_extracts_env(self):
        agent = self.parser.parse(MCP_CONFIG, "config.json")
        bash_server = next(s for s in agent.servers if s.name == "bash")
        assert "GITHUB_TOKEN" in bash_server.env

    def test_extracts_args(self):
        agent = self.parser.parse(MCP_CONFIG, "config.json")
        fs_server = next(s for s in agent.servers if s.name == "filesystem")
        assert "/" in fs_server.args

    def test_format_label(self):
        agent = self.parser.parse(MCP_CONFIG, "config.json")
        assert agent.format == "mcp-config"


class TestOpenAIToolsParser:
    def setup_method(self):
        self.parser = OpenAIToolsParser()

    def test_can_parse_openai_tools(self):
        assert self.parser.can_parse(OPENAI_TOOLS, "tools.json")

    def test_cannot_parse_mcp_config(self):
        assert not self.parser.can_parse(MCP_CONFIG, "config.json")

    def test_parses_tool_name(self):
        agent = self.parser.parse(OPENAI_TOOLS, "tools.json")
        assert agent.servers[0].tools[0].name == "execute_command"

    def test_parses_tool_description(self):
        agent = self.parser.parse(OPENAI_TOOLS, "tools.json")
        assert "shell" in agent.servers[0].tools[0].description.lower()

    def test_format_label(self):
        agent = self.parser.parse(OPENAI_TOOLS, "tools.json")
        assert agent.format == "openai-tools"
