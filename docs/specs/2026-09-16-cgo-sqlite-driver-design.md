# Context1337 CGo SQLite 驱动改造

## 状态

- 日期：2026-09-16
- 状态：Implemented，随 v0.7.9 发版
- 目标仓库：`context1337`
- 触发原因：生产 `context1337-v078` RSS 约 800MiB，根因是 `ncruces/go-sqlite3` 的 WASM 线性内存按连接只涨不缩
- 非目标仓库：PoJun 控制面不热补；本改动随 Context1337 发版上线

## 摘要

将运行时 SQLite 驱动从 `github.com/ncruces/go-sqlite3`（WASM，`CGO_ENABLED=0`）换成 `github.com/mattn/go-sqlite3`（C amalgamation，`CGO_ENABLED=1`）。搜索 SQL、MCP 工具、FTS5 语料和连接池并发策略保持不变。目标是把稳态 RSS 从约 800MiB 降到 native sqlite 的几十 MiB 量级，同时保证 MCP 查询能力不退化。

## 已锁定决策

无需再确认：

- 驱动使用 `mattn/go-sqlite3`，不用 `modernc.org/sqlite`。
- 不调用 `SetMaxOpenConns` / `SetMaxIdleConns` 限流。生产当前约 2 条连接，限连接既降不了 WASM RSS，还会把 MCP 搜索串行化。
- MCP / REST / FTS5 查询语句、tokenizer、ranking、json_extract 过滤保持原样。
- 继续 WAL + `busy_timeout=5000` + `foreign_keys=ON`。
- 运行时镜像从 `gcr.io/distroless/static-debian12` 改为 `gcr.io/distroless/base-debian12`，以提供 glibc。
- 构建标签固定为 `fts5 sqlite_json`。漏标签等于生产搜索不可用。
- 本改动不改 MCP schema、资源 ID、usage 统计语义。

## 目标

- 去掉每连接 256MiB 的 WASM 堆，RSS 回到与 25MiB DB 相称的 native sqlite 水平。
- FTS5 `MATCH` / `bm25`、`json_extract(metadata, ...)`、并发 MCP search 继续可用。
- 本地 `make build` / `make test` / 发布镜像使用同一套 CGo 标签和 DSN。
- 现有 `runtime.db` 文件格式不变，升级只换进程，不迁库。

## 非目标

- 不改搜索相关性、tokenizer、builtin 语料。
- 不引入连接数上限、query timeout、读写分离。
- 不静态链接 sqlite，不改用系统 `libsqlite3`。
- 不在 PoJun 控制面热替换当前 `v0.7.8` 容器；通过 Context1337 `v0.7.9` 镜像发版切换。
- 不把知识库加载进 Go map 来“省 SQLite”。

## 当前问题

`internal/storage/schema.go` 空白导入 `ncruces/go-sqlite3/driver`。该驱动在 wazero 里跑 SQLite，默认 `Memory{Max: 4096}` = 每连接 256MiB 线性内存，只增长不回收。

生产证据：

- 镜像 `CGO_ENABLED=0` + `distroless/static-debian12`
- 磁盘：`runtime.db` / `builtin.db` 各约 25MiB
- 进程 RssAnon 约 800MiB，sqlite fd 约 2 条连接
- 搜索路径是 SQL FTS5，不是把 5127 条资源装进内存

因此 800MiB 是驱动税，不是业务数据。

## 设计

### 驱动与编译

- 依赖改为 `github.com/mattn/go-sqlite3`，删除 ncruces。
- 所有 Go 构建使用 `CGO_ENABLED=1 -tags "fts5 sqlite_json"`。
- 使用 amalgamation，不要 `libsqlite3` tag。
- Dockerfile builder 固定 `golang:1.25-bookworm`，与 `distroless/base-debian12` 的 glibc 对齐。
- Makefile 的 `build` / `test` / `test-integration` / `go run finalize-index` 走同一 `GO_TAGS`。

### DSN

ncruces 的 `_pragma=journal_mode(WAL)` 对 mattn 无效，必须改写，否则 WAL / busy_timeout 会静默丢失。

读写库：

```text
file:<path>?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=1
```

只读打开（builtin/runtime version 读取）：

```text
file:<path>?mode=ro&_busy_timeout=5000
```

DSN 构造集中在 `internal/storage`，禁止各处手写两套参数。

### 连接池

`sql.Open` 后不限制 MaxOpen / MaxIdle。C sqlite 的 page cache 按连接计算，但 native 量级远小于 WASM 256MiB。并发 MCP search 继续走连接池。

### 故障模型

CGo 中 sqlite 致命错误会拖垮整个 `absec`。缓解仅限于已有的 WAL + busy_timeout，以及并发 search 回归测试。不在本轮加 supervisor 或进程内 recover。

### MCP 查询能力

以下行为必须保持，由现有测试守门：

- keyword / 中文 tokenizer search
- vuln `bm25` 排序
- `json_extract` 的 severity / product 过滤
- MCP unified `Search`
- 默认排除 disabled / 默认排除 vuln

新增测试只覆盖驱动合同：WAL、busy_timeout、`json_extract` 可用、并发 reader 不报错、连接池不设上限。不复制一套搜索语料测试。

本地 runtime 语料的 canonical search p95 门禁从 20ms 调整为 100ms。20ms 是 ncruces WASM 在 256MiB 线性内存下的本地数字；CGo sqlite 实测约 50–60ms，对 MCP 仍远低于网络 RTT。该门禁继续防止搜索退化到数百毫秒，不作为产品 SLA。

## 发布

- Context1337 发新版本镜像后，按 PoJun `docs/operations/runbooks/Context1337-runbook.md` canary。
- 验收：MCP search 有结果；容器 RssAnon 明显低于 256MiB×连接数；`PRAGMA journal_mode` 为 `wal`。
- 回滚：切回上一版 ncruces 镜像。DB 文件兼容。

## 测试

- `make test`：现有单元测试 + 驱动合同测试。
- `make test-integration`：带 `integration` 与 sqlite tags。
- 不在本轮强制本地 `make docker`；发布流水线的 `build.test_release_image` 仍是镜像合同门禁。
