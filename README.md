# context1337 — AboutSecurity MCP Server

Standalone MCP resource service that turns [AboutSecurity](https://github.com/wgpsec/AboutSecurity) from a file repo into a consumable API. Like context7, but for security.

## Quick Start

### Docker (recommended)

```bash
# Self-contained build — clones AboutSecurity from GitHub automatically
docker build -t context1337:latest -f build/Dockerfile .
docker run -p 8080:8080 -e ABOUTSECURITY_API_KEY=your-key context1337:latest

# Build with a specific branch/tag
docker build -t context1337:latest -f build/Dockerfile \
  --build-arg ABOUTSECURITY_REF=dev .
```

### Local Development

```bash
# Build & run (requires data/ populated with builtin.db or AboutSecurity content)
make build
./absec serve --port 8080 --data-dir ./data
```

## MCP Client Configuration

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "aboutsecurity": {
      "url": "http://localhost:8080/mcp/sse",
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
      "serverUrl": "http://localhost:8080/mcp/sse"
    }
  }
}
```

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `search_skill` | Search skills by keyword/category/difficulty |
| `get_skill` | Get skill content (metadata/summary/full depth) |
| `list_dicts` | List security dictionaries by type |
| `get_dict` | Get dictionary file content with pagination |
| `search_payload` | Search payloads by keyword or attack type |
| `get_payload` | Get payload file content with pagination |
| `list_tools` | List tool configurations by function |
| `get_tool` | Get full tool YAML configuration |

## REST API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Health check + resource count |
| `GET /api/stats` | Resource statistics by type/source |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ABOUTSECURITY_PORT` | `8080` | HTTP listen port |
| `ABOUTSECURITY_DATA_DIR` | `./data` | Data directory root |
| `ABOUTSECURITY_API_KEY` | (empty=no auth) | API key for Bearer auth |

## Architecture

```
Build time:   AboutSecurity/ → Python+jieba → builtin.db (FTS5 index)
Startup:      cp builtin.db → runtime.db, scan team/ → INSERT
Runtime:      MCP SSE + REST API, pure Go tokenizer for new content
```
