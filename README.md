[中文文档](README.zh-CN.md) | English

# context1337 — AboutSecurity MCP Server

Standalone MCP resource service that turns [AboutSecurity](https://github.com/wgpsec/AboutSecurity) from a file repo into a consumable API. Like context7, but for security.

## Quick Start

### Docker (recommended)

```bash
# Default: clones AboutSecurity from GitHub automatically
make docker

# Use local AboutSecurity repo (skip git clone, faster rebuild)
make docker-local
# or specify path:
make docker-local ABOUTSECURITY_LOCAL=../AboutSecurity

# Pin to a specific branch/tag
make docker-ref ABOUTSECURITY_REF=dev
```

```bash
docker run -p 8088:8088 -e ABOUTSECURITY_API_KEY=your-key context1337:latest
```

### Local Development (recommended for first-time users)

Only requires Go 1.25+ and Python 3 installed on your machine.

```bash
git clone https://github.com/wgpsec/context1337.git
cd context1337

# One command does everything:
# 1. Clones AboutSecurity repo (if not already present)
# 2. Installs Python dependencies (jieba, pyyaml)
# 3. Builds FTS5 search index (builtin.db)
# 4. Compiles Go binary
# 5. Symlinks data directories
# 6. Starts the server
make run

# Build & run (requires data/ populated with builtin.db or AboutSecurity content)
make build
./absec serve --port 8088 --data-dir ./data
```

The server will be available at `http://localhost:8088`.

---

## MCP Client Configuration

### Claude Code (CLI)

```bash
# Add as user-level MCP server (available in all projects)
claude mcp add aboutsecurity --transport http --scope user http://localhost:8088/mcp

# Or project-level only (run from within your project directory)
claude mcp add aboutsecurity --transport http http://localhost:8088/mcp
```

If you set `ABOUTSECURITY_API_KEY` on the server, add the auth header:

```bash
claude mcp add aboutsecurity --transport http --header "Authorization: Bearer your-api-key" --scope user http://localhost:8088/mcp
```

After adding, restart Claude Code and run `/mcp` to verify the connection shows `connected`.

### Claude Desktop

Edit your Claude Desktop config file (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "aboutsecurity": {
      "url": "http://localhost:8088/mcp",
      "headers": {
        "Authorization": "Bearer your-api-key"
      }
    }
  }
}
```

### Cursor

```json
{
  "mcpServers": {
    "aboutsecurity": {
      "serverUrl": "http://localhost:8088/mcp"
    }
  }
}
```

## Usage Examples

Once connected, just ask your AI assistant naturally:

**Skills (penetration testing techniques)**
- "列出所有 exploit 类型的 skill"
- "搜索 sql injection 相关的 skill"
- "获取 sql-injection skill 的完整内容" → uses `get_skill` with `depth=full`, includes references
- "有哪些 cloud 安全相关的技能？"

**Dictionaries (wordlists for brute-force)**
- "搜索弱口令字典"
- "列出 auth 类型的字典"
- "查看 Top100 密码字典内容" → uses `get_dict` with pagination

**Payloads (attack payloads)**
- "Show me XSS payloads"
- "搜索 SSRF 相关的 payload"
- "查看 SQLi union 注入的 payload"

**Tools (security tool configs)**
- "查看 nmap 工具配置"
- "列出所有扫描类工具"
- "Tell me about sqlmap tool"

The AI will automatically call the right MCP tools to find relevant security knowledge.

## Available MCP Tools (12)

### Skills
| Tool | Description |
|------|-------------|
| `list_skills` | List skills by category/difficulty with pagination |
| `search_skill` | Search skills by keyword with pagination |
| `get_skill` | Get skill detail (depth: metadata/summary/full). `depth=full` includes references/ content |

### Dictionaries
| Tool | Description |
|------|-------------|
| `list_dicts` | List dictionaries by category with pagination |
| `search_dicts` | Search dictionaries by keyword with pagination |
| `get_dict` | Read dictionary file content with line-level pagination |

### Payloads
| Tool | Description |
|------|-------------|
| `list_payloads` | List payloads by category with pagination |
| `search_payload` | Search payloads by keyword with pagination |
| `get_payload` | Read payload file content with line-level pagination |

### Tools
| Tool | Description |
|------|-------------|
| `list_tools` | List tool configurations by category with pagination |
| `search_tools` | Search tools by keyword with pagination |
| `get_tool` | Get full YAML configuration for a tool |

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make run` | Build + index + start server (first run auto-clones data) |
| `make build` | Compile Go binary only |
| `make index` | Build FTS5 search index only |
| `make test` | Run unit tests |
| `make test-integration` | Run integration tests |
| `make docker` | Build Docker image |
| `make clean` | Remove binary, databases, and symlinks |

## REST API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Health check + resource count |
| `GET /api/stats` | Resource statistics by type/source |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ABOUTSECURITY_PORT` | `8088` | HTTP listen port |
| `ABOUTSECURITY_DATA_DIR` | `./data` | Data directory root |
| `ABOUTSECURITY_API_KEY` | (empty=no auth) | API key for Bearer auth |

## Architecture

```
Build time:   AboutSecurity/ → Python+jieba → builtin.db (FTS5 index)
Startup:      cp builtin.db → runtime.db, scan team/ → INSERT
Runtime:      MCP Streamable HTTP + REST API, pure Go tokenizer for new content
```
