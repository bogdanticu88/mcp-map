# Changelog

All notable changes to mcpmap are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] - 2026-05-15

Initial public release.

### Detection rules (24 total)

**CRITICAL**
- MCM-001 Shell / Command Execution Capability
- MCM-002 Arbitrary Code Execution Capability
- MCM-003 Credential and Secret Store Access
- MCM-004 Process Management Capability

**HIGH**
- MCM-005 Filesystem Write Access
- MCM-006 Unrestricted Network Fetch / HTTP Request
- MCM-007 Email Send Capability
- MCM-008 Git Write / Repository Push Access
- MCM-009 Database Write / Delete Access
- MCM-010 API Key or Token Exposed in Server Environment
- MCM-011 Broad Filesystem Access (Root or Home Directory)
- MCM-012 Overprivileged MCP Server
- MCM-020 Unpinned Package Version in Auto-Accept Runner
- MCM-021 Adversarial Instructions Embedded in Tool Description
- MCM-022 High-Entropy Secret in Server Environment
- MCM-024 Package Name Resembles Trusted Publisher (Typosquatting)

**MEDIUM**
- MCM-013 Unrestricted Web Browsing / Browser Automation
- MCM-014 Unverified Third-Party MCP Server
- MCM-015 Tool Missing Description (Tool Confusion Risk)
- MCM-016 Sensitive Directory Read Access
- MCM-023 Remote MCP Server over HTTP/SSE

**LOW**
- MCM-017 Calendar Write Access
- MCM-018 Social Media Post Capability
- MCM-019 Push Notification Send Capability

### Features

- YAML rule engine: load built-in rules or supply your own via `--rules`
- Claude Desktop config detection on Windows, macOS, and Linux via `mcpmap find`
- OpenAI tool definition support (`tools: [...]` array format)
- Remote MCP server support: servers configured with a `url` field are scanned; auth headers are checked for exposed secrets
- Entropy-based secret detection: Shannon entropy >= 4.5 bits/char on env/header values >= 20 chars
- Unpinned package detection: flags `npx -y @pkg/name` without a version pin
- Typosquatting detection: Levenshtein distance <= 2 against trusted publisher names
- Adversarial instruction detection: 20+ prompt-injection phrase patterns in tool descriptions
- Context-aware remediation: advice names the exact path, key, or package to fix
- Suppression / allow-list via `.mcpmap-ignore` with per-rule, per-server, and wildcard entries
- Baseline / diff mode via `--baseline` and `--save-baseline` for CI regression gating
- Output formats: Markdown, JSON, HTML (dark-mode report), SARIF
- REST API (`mcpmap serve`) with `/analyze`, `/rules`, and `/health` endpoints
- CI gate via `--fail-on`: exit code 1 on threshold breach, exit code 2 on bad inputs
- Custom rules: extend or replace the built-in rule set with a YAML file
- `--summary`: terminal-only summary table without the full report
- `--ascii`: ASCII-only output, no badges
- `--show-suppressed`: include suppressed findings in the report
- OWASP LLM Top 10 and MITRE ATLAS mappings on every finding
