# Context1337 MCP Usage Analytics 设计规范

## 状态

- 日期：2026-08-11
- 状态：Phase 1 implemented and verified locally
- 影响仓库：`context1337`
- 后续集成：`pojun`（不在本阶段实现）

## 背景

生产访问日志已经证明 Context1337 MCP 有稳定且较高的实际使用量，但目前只能从反向代理日志统计 HTTP 请求，无法回答以下产品问题：

- 哪些 MCP tools 被实际调用；
- 调用成功率、耗时和响应体积如何；
- 主要由哪一类客户端使用；
- 当前是否存在活跃 MCP session；
- 发布前后调用量或错误率是否发生变化。

现有 `--benchmark` 面向开发评测，会把所有 tool input 逐事件写入 JSONL，既无有界聚合，也无法直接区分搜索命中和内容缺口，因此不能作为生产产品分析方案。

## 决策

### 采集边界

Context1337 是 MCP 使用事实的权威采集点。它能准确观察 HTTP 请求、MCP tool 名称、执行结果、耗时和响应体积；PoJun 无法观察直接访问 Context1337 的 Codex、Claude 或其他客户端。

PoJun 后续只负责：

- 把 Context1337 的聚合指标与 PoJun 管理的项目、用户或组织维度组合；
- 持久化周期快照并展示趋势；
- 提供产品分析页面和告警。

本阶段不修改 PoJun。

### 数据模型

Context1337 在进程内维护有界、单调累计的聚合计数器，不保存逐请求事件。快照包含：

- `started_at`、`generated_at`；
- `mcp_http.requests_total`；
- `mcp_http.requests_by_status_class`；
- `mcp_http.requests_by_client_family`；
- `mcp_http.duration_ms` histogram；
- `mcp_http.response_bytes` histogram；
- `mcp_http.active_requests`；
- `mcp.active_sessions`；
- `tools.calls_total`；
- `tools.calls_by_name`；
- `tools.calls_by_status`；
- `tools.duration_ms` histogram；
- `tools.response_bytes` histogram；
- `search.queries_total`、`matched_total`、`zero_result_total`、`error_total`；
- `search.result_count` histogram；
- `search.queries`：完整规范化查询及其过滤条件、调用/命中/零结果/错误计数；
- `search.zero_result_queries`：包含至少一次零结果的查询子集；
- `search.query_capacity`、`tracked_queries`、`dropped_queries_total`。

除搜索查询聚合外，所有 map 的键来自固定允许列表。搜索查询聚合最多跟踪 10,000 个不同的“查询文本 + type/category/severity/product”组合；达到容量后不再接纳新组合，并递增 `dropped_queries_total`，已有组合继续精确计数。

### 维度规范化

Client family 仅允许以下值：

- `pojun-agent`
- `codex`
- `claude`
- `python`
- `other`

分类仅在请求处理期间读取 User-Agent，聚合后立即丢弃原值。

Tool name 仅允许 Context1337 当前注册的 lite/full tool 名称；未知名称统一归入 `other`。状态仅允许 `success` 和 `error`。

### 搜索查询分析边界

产品所有者明确要求以分析完整性优先，不对搜索关键词做隐私脱敏：

- 记录 `search_security` 及 full mode `search_*` 的完整查询；
- 仅做大小写统一、首尾/连续空白规范化，以合并语义相同的查询；
- 记录 type、category、severity、product 过滤条件，避免把“指定类型无结果”误判为全库缺失；
- 单次零结果查询立即出现在输出中，不设最小出现次数；
- 不对 IP、域名、URL、路径、产品、漏洞编号或其他查询内容脱敏；
- 空 query 属于 list 操作，不进入关键词统计。

仍不得采集、保存或返回与搜索分析无关的：

- 其他 tool arguments；
- API key、Authorization header 或 query-string token；
- IP、Forwarded headers；
- MCP session ID；
- 完整 User-Agent；
- MCP response 内容；
- 单次调用时间戳或可关联的事件 ID。

metrics 模块不得依赖或复用 `internal/mcp/benchlog`。

### 查询入口与鉴权

新增：

```text
GET /api/usage
Authorization: Bearer <ABOUTSECURITY_API_KEY>
```

约束：

1. `/api/usage` 复用 MCP 与 REST API 的 `ABOUTSECURITY_API_KEY`，不维护第二把密钥。
2. API key 为空时不注册 `/api/usage`，避免无鉴权暴露使用数据。
3. 缺失或错误 API key 返回统一的 `401`，不泄露配置状态。
4. 响应设置 `Cache-Control: no-store`。

此约束由 2026-08-12 的产品决策覆盖原独立 Usage Token 设计。认证关闭时普通 MCP/REST
仍保持原行为，但 usage endpoint 单独关闭并返回 `404`。

### 生命周期和持久化

计数器从 Context1337 进程启动时开始，进程重启后归零。快照中的 `started_at` 用于调用方识别 reset。

本阶段不在 Context1337 引入 SQLite 表、日志轮转或定时任务。后续 PoJun 集成按固定周期拉取快照，以 `(instance, started_at)` 识别计数器世代并计算增量；这是实现小时/天趋势和长期留存的正确层级。

### MCP 行为兼容

- metrics 记录发生在现有 MCP HTTP handler 和 tool wrapper 外层；
- 不修改 tool schema、prompt、search、detail、file 或响应内容；
- 不改变 MCP auth、session、streaming 和 tool-mode dispatch；
- 指标采集失败不得影响 MCP 请求；
- HTTP streaming wrapper 必须保留 `http.Flusher`/`ResponseController` 能力。

## 实现结构

```text
internal/usage/
  collector.go       bounded counters, histograms, snapshot
  http.go            MCP HTTP instrumentation

internal/mcp/handler.go
  tool wrapper records name/status/duration/response size
  MCP HTTP handler records client/status/duration/response size

internal/api/router.go
  GET /api/usage protected by the shared MCP API key

internal/config/config.go
  ABOUTSECURITY_API_KEY

cmd/absec/main.go
  creates one collector shared by MCP and usage endpoint
```

## Histogram Buckets

Duration buckets are non-cumulative, mutually exclusive ranges:

```text
lt_10, lt_50, lt_250, lt_1000, gte_1000
```

Response byte buckets are non-cumulative, mutually exclusive ranges:

```text
lt_1k, lt_10k, lt_100k, gte_100k
```

固定 bucket 避免高基数，并足以识别延迟和响应体积趋势。PoJun 后续展示时可以计算区间占比，不应把 bucket 当作原始事件重放。

## TDD 验收

1. Collector 对 HTTP status、client family、duration、response size 做正确且有界的聚合。
2. Collector 对 tool name、success/error、duration、response size 做正确聚合。
3. 任意未知 tool 和 User-Agent 只能进入 `other`，不得成为新 map key。
4. MCP initialize 和真实 tool call 后，相应 HTTP/tool 指标递增且 MCP 响应保持有效。
5. 搜索查询按规范化文本和过滤条件精确聚合，单次零结果立即可见。
6. 搜索成功、零结果、执行错误和结果数量 bucket 分别正确计数。
7. 搜索查询容量固定为 10,000，超限有显式 dropped 计数。
8. 非搜索 tool arguments、HTTP query、User-Agent 原文不会进入快照。
9. tool 执行错误计入 `error`，不计入 `success`。
10. MCP API key 为空时 endpoint 为 `404`；缺失或错误 key 为 `401`；正确 key 为 `200`。
11. `/mcp` 与 `/api/usage` 接受同一把 `ABOUTSECURITY_API_KEY`。
12. race test 不报告并发读写问题。
13. 全量 Go test、`go vet` 和真实本地 HTTP smoke test 通过。

## 后续阶段

PoJun 集成需另行设计和决策，至少包括：

- Context1337 instance identity 与 token 管理；
- 拉取频率、断点和 counter reset 处理；
- 小时/天聚合留存周期；
- super admin 可见范围；
- PoJun 项目调用与公网直接调用的归属边界；
- dashboard、错误率和延迟告警。

在上述设计完成前，Context1337 不推断用户、组织或项目身份。

## Phase 1 实施结果

- 新增并发安全的内存聚合器和固定维度 histograms。
- MCP HTTP handler 统计请求状态、client family、耗时、响应体积和 active requests。
- tool wrapper 统计真实 tool 名称、success/error、耗时和响应体积。
- `Service.Search` 统计完整规范化查询、过滤条件、最终结果总数、零结果和搜索错误；不记录其他 tool 输入或响应内容。
- active sessions 直接读取 MCP SDK 的 lite/full server session 集合。
- 新增受 MCP API key 保护的 `GET /api/usage`；`ABOUTSECURITY_API_KEY` 为空时稳定返回 `404`。
- 保持现有 `NewRouter`、`NewMCPServer` 调用向后兼容，未修改 tool schema 或 MCP 响应。
- 本地真实服务验证了 initialize、tool call、client family、session 和鉴权指标。
- PoJun、生产配置和生产容器均未修改。
