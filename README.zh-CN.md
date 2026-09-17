[English](README.md) | 中文文档

![context1337 — Pentest knowledge base for AI agents](docs/images/banner.jpg)

# context1337 — AboutSecurity MCP 服务

独立的 MCP 资源服务，将 [AboutSecurity](https://github.com/wgpsec/AboutSecurity) 从文件仓库转变为可消费的 API。类似 context7，但专为安全领域打造。

## 效果展示

**搜索安全资源**
![search](docs/images/demo-search-zh.png)

**漏洞情报查询**
![vuln](docs/images/demo-vuln-zh.png)

**AD 域攻击技能详情**
![skill](docs/images/demo-skill-zh.png)

## 快速开始

### Docker（推荐）

```bash
# 默认：自动从 GitHub 克隆 AboutSecurity
make docker

# 使用本地 AboutSecurity 仓库（跳过 git clone，更快）
make docker-local
# 或指定路径：
make docker-local ABOUTSECURITY_LOCAL=../AboutSecurity

# 指定特定分支/标签
make docker-ref ABOUTSECURITY_REF=dev
```

```bash
docker run -p 1337:1337 -e ABOUTSECURITY_API_KEY=your-key context1337:latest

# 可选：打开 /admin，并把管理台密钥和 custom 资源持久化到 runtime 卷
docker run -p 1337:1337 \
  -e ABOUTSECURITY_API_KEY=your-key \
  -e ABOUTSECURITY_ADMIN_KEY=your-admin-key \
  -v context1337-runtime:/app/data/runtime \
  context1337:latest
```

### 本地开发（推荐首次使用者）

需要 Go 1.25+（gotip）、用于 CGo sqlite（`mattn/go-sqlite3`）的 C 编译器，以及 Python 3。`make build` / `make test` 会启用 FTS5 和 JSON。

```bash
git clone https://github.com/wgpsec/context1337.git
cd context1337

# 一条命令搞定一切：
# 1. 克隆 AboutSecurity 仓库（如果还没有）
# 2. 安装 Python 依赖（jieba、pyyaml）
# 3. 构建 FTS5 全文搜索索引（builtin.db）
# 4. 编译 Go 二进制文件
# 5. 创建数据目录软链接
# 6. 启动服务
make run

# 手动构建和运行
make build
./absec serve --port 1337 --data-dir ./data  # 默认：--tool-mode lite
```

服务启动后访问 `http://localhost:1337`。

---

## MCP 客户端配置

### Claude Code（CLI）

```bash
# 添加为用户级 MCP 服务（所有项目可用）
claude mcp add aboutsecurity --transport http --scope user http://localhost:1337/mcp

# 或仅项目级（在项目目录内运行）
claude mcp add aboutsecurity --transport http http://localhost:1337/mcp
```

删除用 `claude mcp remove aboutsecurity -s user`

如果服务端设置了 `ABOUTSECURITY_API_KEY`，需要添加认证头：

```bash
claude mcp add aboutsecurity --transport http --header "Authorization: Bearer your-api-key" --scope user http://localhost:1337/mcp
```

添加后重启 Claude Code，运行 `/mcp` 确认连接状态为 `connected`。

### Claude Desktop

编辑配置文件（macOS 路径：`~/Library/Application Support/Claude/claude_desktop_config.json`）：

```json
{
  "mcpServers": {
    "aboutsecurity": {
      "url": "http://localhost:1337/mcp",
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
      "serverUrl": "http://localhost:1337/mcp"
    }
  }
}
```

## 使用示例

连接后，直接用自然语言与 AI 助手对话：

**跨类型搜索**
- "搜索 SQL 注入相关资源" → `search_security(query="SQL injection")` 同时找到 skill、payload
- "有哪些 XSS payload？" → `search_security(query="XSS", type="payload")`
- "有哪些漏洞利用技能？" → `search_security(type="skill", category="exploit")`

**获取详细知识**
- "详细讲解 SQL 注入攻击技术" → 先搜索，再调用 `get_security_detail(id="absec://builtin/skill/sql-injection", depth="full")` 获取参考资料
- "nmap 扫描怎么做？" → `get_security_detail(id="absec://builtin/skill/nmap-scan")` 返回方法论
- "jenkins 的后渗透手段有哪些"

**读取数据文件**
- "给我常见弱口令字典前 100 行" → 先搜索，再调用 `read_security_file(id="absec://builtin/dict/Auth%2Fpassword%2FTop100.txt")`
- "XSS 事件触发的 payload 有哪些？" → `read_security_file(id="absec://builtin/payload/XSS%2Fevents.txt")`

**搜索漏洞**
- "查找 Apache 高危漏洞" → `search_security(query="Apache", type="vuln", severity="CRITICAL")`
- "列出所有中间件漏洞" → `search_security(type="vuln", category="middleware")`
- "获取 Log4j RCE 漏洞详情" → 先搜索，再调用 `get_security_detail(id="absec://builtin/vuln/CVE-2021-44228", depth="full")`

搜索结果会返回稳定 `id`，例如 `absec://builtin/skill/sql-injection`。推荐把这个 `id` 传给详情或文件读取工具，因为它保留了明确的数据源和资源身份。旧参数 `name`/`type`、`path`/`type` 仍然兼容，但当多个数据源存在同名资源时，`id` 可以避免歧义。

例如 `absec://builtin/vuln/CVE-2021-44228` 和 `absec://nuclei/vuln/CVE-2021-44228` 可以同时存在。`get_security_detail(name="CVE-2021-44228", type="vuln")` 无法指定来源，而稳定 ID 可以精确选择目标资源。

AI 会自动调用正确的 MCP 工具来查找相关安全知识。

## 可用 MCP 工具

默认为 **精简模式**（3 个工具）。使用 `--tool-mode full` 启用 12 个分类工具。如果 AI 模型未能主动调用工具，可切换到 full 模式，提供更细粒度的 12 个专用工具以提升触发率。

### 精简模式（默认，3 个工具）

| 工具 | 说明 |
|------|------|
| `search_security` | 搜索或列出所有资源类型（skill、dict、payload），结果包含稳定 `id`。搜索漏洞须显式指定 type="vuln"（默认搜索排除漏洞）。漏洞支持 severity 和 product 过滤 |
| `get_security_detail` | 通过稳定 `id`（推荐）或旧参数 `name` + `type` 获取 skill / vuln 详情 |
| `read_security_file` | 通过稳定 `id`（推荐）或旧参数 `path` + `type` 按行分页读取字典或 payload 文件内容 |

### 完整模式（12 个工具）

> 如果模型能力弱，或者触发不足，就用 full 模式，提供完整 mcp tool

| 工具 | 说明 |
|------|------|
| `search_skill` | 按关键词搜索渗透测试技能，结果包含稳定 `id` |
| `search_dicts` | 按关键词搜索密码字典，结果包含稳定 `id` |
| `search_payload` | 按关键词搜索攻击载荷，结果包含稳定 `id` |
| `search_vuln` | 按关键词搜索漏洞库，支持 severity 和 product 过滤，结果包含稳定 `id` |
| `list_skills` | 浏览所有技能，结果包含稳定 `id` |
| `list_dicts` | 浏览所有字典，结果包含稳定 `id` |
| `list_payloads` | 浏览所有载荷，结果包含稳定 `id` |
| `list_vulns` | 列出漏洞（默认 50 条），支持 category/severity/product 过滤，结果包含稳定 `id` |
| `get_skill` | 通过稳定 `id`（推荐）或旧 name 获取技能详情（支持 depth 和 references） |
| `get_dict` | 通过稳定 `id`（推荐）或旧 path 按行分页读取字典文件 |
| `get_payload` | 通过稳定 `id`（推荐）或旧 path 按行分页读取载荷文件 |
| `get_vuln` | 通过稳定 `id`（推荐）或旧 name 获取漏洞详情（CVE/CNVD ID），支持 brief/full 深度（含 PoC） |

## Makefile 命令

| 命令 | 说明 |
|------|------|
| `make run` | 构建 + 索引 + 启动服务（首次运行自动克隆数据） |
| `make build` | 仅编译 Go 二进制文件 |
| `make index` | 仅构建 FTS5 搜索索引 |
| `make test` | 运行单元测试 |
| `make test-integration` | 运行集成测试 |
| `make docker` | 构建 Docker 镜像（从 GitHub 克隆 AboutSecurity） |
| `make docker-local` | 使用本地 AboutSecurity 仓库构建镜像 |
| `make docker-ref` | 指定分支/标签构建镜像 |
| `make clean` | 清理二进制文件、数据库和软链接 |
| `make clean-benchmark` | 清理 benchmark 日志 |

## REST API

| 接口 | 说明 |
|------|------|
| `GET /health` | 存活探针，免鉴权，不暴露 source 计数 |
| `GET /admin` | 管理台（独立 `ABOUTSECURITY_ADMIN_KEY`；未设置则关闭） |
| `GET /api/health` | 需认证；按已授权 source 返回已启用资源计数 |
| `GET /api/stats` | 需认证；按类型/来源统计已启用资源（仅已授权 source） |
| `GET /api/usage` | MCP 使用与搜索关键词聚合（仅 write 密钥；关闭认证时禁用） |
| `GET /api/resources` | 分页列表（仅已授权 source，含 disabled） |
| `POST /api/resources` | 创建自定义资源（需要 write 且含 `custom`；source 强制为 custom） |
| `PUT /api/resources/{id}` | 编辑自定义资源（需要 write 且含 `custom`，否则 403） |
| `DELETE /api/resources/{id}` | 删除自定义资源（需要 write 且含 `custom`，否则 403） |
| `PUT /api/resources/{id}/toggle` | 切换启用/禁用（需要 write；仅已授权 source） |
| `PUT /api/resources/batch-toggle` | 按 type/category/source 批量切换（需要 write；仅已授权 source） |

### 资源管理

资源表有 `enabled` 字段（默认 `1`）。禁用的资源在 MCP 工具查询（搜索、列表、详情）中不可见，但 `GET /api/resources` 仍可查看。列表/搜索/详情需要 `read`；创建/编辑/删除/启停需要 `write`。

**切换单个资源：**
```bash
curl -X PUT http://localhost:1337/api/resources/42/toggle \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

**批量切换（按分类/数据源）：**
```bash
curl -X PUT http://localhost:1337/api/resources/batch-toggle \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false, "filter": {"type": "skill", "category": "web"}}'
```

**创建自定义资源：**
```bash
curl -X POST http://localhost:1337/api/resources \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"type": "skill", "name": "my-technique", "category": "web", "description": "...", "body": "..."}'
```

自定义资源的 `source` 由服务端强制设为 `custom`，可编辑和删除。内置资源不可修改或删除（返回 403）。

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ABOUTSECURITY_PORT` | `1337` | HTTP 监听端口 |
| `ABOUTSECURITY_DATA_DIR` | `./data` | 数据目录根路径 |
| `ABOUTSECURITY_API_KEY` | （空=无认证） | 引导管理员密钥：可见全部 source（`builtin`/`nuclei`、`team`、`custom`）且可写。为空时关闭认证和 `GET /api/usage` |
| `ABOUTSECURITY_API_KEYS_FILE` | `{dataDir}/runtime/api-keys.json` | 额外 API 密钥 JSON，按 source/access 授权。文件不存在表示没有额外密钥。管理台会创建并写入此文件。需要挂持久化 runtime 卷，不要打进镜像或 team zip |
| `ABOUTSECURITY_ADMIN_KEY` | （未设置） | 仅用于 `/admin` 的独立超管密钥，不能与任何 MCP/REST 密钥相同。为空则关闭管理台 |
| `ABOUTSECURITY_TOOL_MODE` | `lite` | 工具注册模式：`lite`（3 个工具）或 `full`（12 个工具） |
| `NUCLEI_TEMPLATES_DIR` | 原生运行为空；官方镜像为内置快照路径 | nuclei-templates 仓库根目录，启用第二数据源 |
| `NUCLEI_MIN_SEVERITY` | `high` | nuclei 漏洞模板最低导入级别：`critical`/`high`/`medium`/`low` |

## API 密钥 RBAC

每把密钥有两轴权限：**sources**（`builtin`、`team`、`custom`）和 **access**（`read` 与 `write` 可同时勾选）。授权 `builtin` 即包含 `nuclei`。`ABOUTSECURITY_API_KEY` 仍是向后兼容的管理员密钥。额外密钥来自 `ABOUTSECURITY_API_KEYS_FILE`：

```json
[
  {"id": "public-mcp", "key": "replace-me", "sources": ["builtin"], "access": ["read"]},
  {"id": "pojun-agent", "key": "replace-me", "sources": ["builtin", "team"], "access": ["read"]},
  {"id": "ops", "key": "replace-me", "sources": ["builtin", "team", "custom"], "access": ["read", "write"]}
]
```

未带 `source=` 的搜索/列表/MCP 会静默限制在已授权 source。显式传入未授权 `source=` 返回 403。按 id 读取隐藏 source 与资源不存在相同，返回 not-found。`read` 才能做 MCP/REST 查询；`write` 才能做 custom CRUD、toggle 和 `GET /api/usage`。两者可同时有，也可分开给。toggle 只作用于已授权 source。`/health` 继续免鉴权，且不暴露 source 计数。旧格式 `"access": "write"` 仍表示读写都有。

## 管理台

打开 `/admin`，用 `ABOUTSECURITY_ADMIN_KEY` 登录。这把超管密钥与 MCP/REST 密钥隔离：它不能调 `/mcp` 或 `/api/*`，MCP/REST 密钥也进不了管理台。未设置时 `/admin` 返回 404。

管理台主功能是 MCP/REST 密钥管理：创建、改 `sources`/`access`、轮换、删除。明文只在创建或轮换时显示一次。环境变量里的 bootstrap 密钥只读。管理台写入 `ABOUTSECURITY_API_KEYS_FILE` 或 `data/runtime/api-keys.json`，立即对 MCP/REST 生效。资源检索/启停和用量是附带页面。

## 数据源

### 默认数据源：AboutSecurity

服务启动时自动加载 [AboutSecurity](https://github.com/wgpsec/AboutSecurity) 仓库中的 skill、dict、payload、vuln 数据，构建 FTS5 全文搜索索引。这是唯一的必选数据源。

### 第二数据源：nuclei-templates

可选接入 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) 漏洞情报，补充 AboutSecurity 的覆盖范围。Context1337 导入 HTTP 下的 `cves`、`cnvd`、`vulnerabilities`、`misconfiguration` 和 `default-logins` 类别；暴露面/探测、子域接管及非 HTTP 协议模板会明确排除。直接运行原生二进制时，只有设置 `--nuclei-dir` 或 `NUCLEI_TEMPLATES_DIR` 才会启用。

官方 Docker 镜像会打包发布构建时上述支持类别的最新快照，并按最低 `high` 级别默认启用；直接运行原生二进制时仍为按需开启。构建时解析出的上游 commit 会写入镜像 label `org.opencontainers.image.nuclei-templates.revision`，运行中的容器不会联网拉取或自动更新模板。

**启用方式：**

```bash
# 命令行参数（推荐）
./absec serve --nuclei-dir /path/to/nuclei-templates

# 仅导入 critical 级别（默认 high，即 critical+high）
./absec serve --nuclei-dir /path/to/nuclei-templates --nuclei-min-severity critical

# 扩大范围到 medium
./absec serve --nuclei-dir /path/to/nuclei-templates --nuclei-min-severity medium

# 或通过环境变量
NUCLEI_TEMPLATES_DIR=/path/to/nuclei-templates ./absec serve
```

**参数说明：**

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--nuclei-dir` | nuclei-templates 仓库根目录路径，不传则不启用 | （空=不启用） |
| `--nuclei-min-severity` | 最低导入级别：`critical` \| `high` \| `medium` \| `low` | `high` |

默认导入支持类别中的 critical+high 模板。

**同步行为：** 服务启动时会自动检查 nuclei 配置。首次设置 `--nuclei-dir`、更换目录、调整 severity，都会只重建 `source=nuclei` 的资源，不会删除 runtime DB，也不会影响 `custom` 资源。下次用相同配置启动会直接复用已有 nuclei 索引。

如果不再传 `--nuclei-dir`，服务会在启动时移除 `source=nuclei` 资源，相当于关闭第二数据源。

---

## 私有 team overlay

把私有语料挂到 `data/team`，目录结构和 AboutSecurity 相同（`Vuln/`、`Dic/`、
`Payload/`、`skills/`）。Context1337 以 `source=team` 建索引，并和 `builtin` 一起检索。
不要把私有文件打进镜像或 `builtin.db`。

启动时会计算 team 目录快照，只有快照变化才重建 `source=team` 资源，不会删
`runtime.db`，也不会动 `custom`。目录没变的重启会复用已有 team 行和 ID。替换 volume
里的文件后重启进程即可，不要删 `runtime.db`。

---

## 架构

```
构建阶段:   AboutSecurity/ → Python+jieba 分词 → builtin.db（FTS5 索引）
启动阶段:   缺失或版本变化时复制 builtin.db → runtime.db
            team/ 目录快照变化时同步 → INSERT（source=team）
            [可选] 按配置同步支持的 nuclei HTTP 类别 → INSERT（source=nuclei）
运行阶段:   MCP Streamable HTTP + REST API，Go 原生分词器处理新内容
```

## WgpSec Agentic 生态

context1337 是 **WgpSec Agentic 生态** 的服务层 — 连接结构化安全知识与自主 AI Agent。

```
┌───────────────────── WgpSec Agentic Ecosystem ─────────────────────┐
│                                                                     │
│  知识 ➜ 服务 ➜ 执行 ➜ 验证                                          │
│                                                                     │
│  AboutSecurity ──▶ context1337 ──▶ tchkiller ──▶ benchmark-platform │
│                    (本仓库)         (渗透 Agent)    (CTF 靶场)       │
│                                         ▲                           │
│                                    破军 PoJun (通用求解引擎)         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

| 项目 | 定位 |
|------|------|
| [AboutSecurity](https://github.com/wgpsec/AboutSecurity) | 结构化渗透知识库（Skills、Dic、Payload、Vuln） |
| [context1337](https://github.com/wgpsec/context1337) | MCP Server — 将 AboutSecurity 转为 AI Agent 可检索的 API |
| [tchkiller](https://github.com/wgpsec/tchkiller) | 智能渗透测试 Agent，多轮决策 + 团队协作 |
| [benchmark-platform](https://github.com/wgpsec/benchmark-platform) | 浑象 CTF 靶场竞赛平台，评估 Agent 攻防能力 |
| [benchmark-challenges](https://github.com/wgpsec/benchmark-challenges) | 靶场数据仓库 — 通过 GitHub Releases 打包分发 |
| 破军 PoJun | 通用 AI 问题求解引擎（内部项目，未开源） |
