# Security Concept Search 实施计划

## 实施状态

- [x] Slice 0：基线、规格与 worktree 边界确认。
- [x] Slice 1：概念查询、跨语言召回、ASCII 词边界和查询复杂度上限。
- [x] Slice 2：canonical 排序、reranked relevance cutoff 和 stable ID 尾键。
- [x] Slice 3：MCP/REST `search_version`、真实 corpus golden 与性能门禁。
- [x] Slice 4：PoJun Resolver 版本隔离、search contract trace 与 OODA/session 回归。

## TDD 验收记录

每个行为均先增加失败测试，再实现最小改动；最后两项收口 RED 分别证明了：完全同分候选仍依赖输入顺序，以及 256-byte/QueryPlan version 契约尚未实现。

- context1337：`go test ./...` 全部通过。
- context1337 index builder：`22 passed`。
- 真实 runtime corpus：8 条 canonical golden 全部 Top 1。
- 真实 runtime corpus 120 次查询：p95 `4.58ms`，门禁为 `<=20ms`；相同机器 legacy HEAD p95 `2.47ms`，新实现约 `1.86x`，满足 `<=2x`。
- PoJun 知识 Resolver、scheduler gate、Reason/Review、Server、execution/session 定向套件：`80 passed`。
- PoJun Dispatcher 非 integration/e2e 扩大回归：`1004 passed`；固定端口 SSE 用例在扩大套件中偶发 connection reset，单独复跑 `1 passed`。
- 真实跨进程 smoke：通过 PoJun MCP 调用路径查询 `JWT algorithm confusion`、`JWT none algorithm bypass`、`JWT authentication bypass`，均返回 `security-concepts-v1` 且 Top 1 为 `absec://builtin/skill/jwt-attack-methodology`。

## 原则

- 严格采用 vertical-slice TDD；每次只增加一个可观察行为。
- 每个 cycle 都先看 RED，再写最小实现，GREEN 后才 refactor。
- 测试尽量通过公共 `search.Search`、MCP `Service.Search`、REST handler 和 PoJun Resolver 接口，不测试私有实现形状。
- 不在 RED 状态重构。
- 不修改数据库 schema，不重建 runtime DB。
- 不引入 LLM、embedding 或查询 fallback。

## Slice 0：规格与基线

### Cycle 0.1：基线测试

1. 运行 `go test ./...`，记录现有结果。
2. 运行 `python3 -m pytest build/test_build_index.py -q`。
3. 用真实 runtime.db/MCP 记录 JWT、SQL Injection、File Upload、OAuth、Java Deserialization 当前 Top 结果。
4. 确认两个仓库 worktree 边界，保留同事并行改动。

完成条件：基线可重复、context1337 worktree 干净。

## Slice 1：边界安全的跨语言概念召回

### Cycle 1.1：JWT algorithm confusion 可召回 canonical Skill

**RED**

- 在 `internal/search/index_test.go` 通过公共 `Search` 插入 canonical JWT Skill 和 decoy Skills。
- 查询 `JWT algorithm confusion`。
- 断言结果包含 `jwt-attack-methodology`。

**GREEN**

- 增加最小 query concept expansion，仅支持 JWT 与 algorithm confusion。
- group 内 OR、group 间 AND。

**REFACTOR**

- 提取结构化 FTS token escaping/building，禁止拼接原始 alias。

### Cycle 1.2：none algorithm bypass 保留全部语义

**RED**

- 查询 `JWT none algorithm bypass`。
- canonical Skill 仅含 `alg none`/`空算法`/中文绕过时仍必须进入候选。
- 只有 `JWT`、缺少 none/bypass 语义的 decoy 不得进入候选。

**GREEN**

- 增加 `jwt_none_algorithm`、`bypass` 等价 group。
- 不删除 bypass，不执行第二次查询。

### Cycle 1.3：中英文反向等价

**RED**

- `JWT 算法混淆` 能命中只有英文 `algorithm confusion` 的 Skill。

**GREEN**

- aliases 双向落入同一个 Concept Group。

### Cycle 1.4：ASCII 词边界

**RED**

- 通过公共 tokenizer 断言 `source audit` 不包含 `rce`。
- `RCE source audit` 仍识别独立 RCE。

**GREEN**

- ASCII alias 使用 Unicode/ASCII word boundary；CJK 保持完整连续匹配。

### Cycle 1.5：安全限制

**RED**

- FTS 运算符、引号和超长 alias 不能改变表达式结构。
- 超过 group/token 上限返回明确错误。

**GREEN**

- 引入 bounded `QueryPlan` 与 typed expression builder。

Slice 1 门禁：`go test ./internal/tokenize ./internal/search`。

## Slice 2：Canonical Skill 确定性排序

### Cycle 2.1：JWT authentication bypass Top 1

**RED**

- 通过公共 `Search` 构造 cookie/java/php/jwt 四个真实形态候选。
- 查询 `JWT authentication bypass`。
- 断言 JWT methodology Top 1。

**GREEN**

- 在 SearchResult 中计算 name anchor coverage。
- 在 BM25 前增加最小 name-anchor 排序键。

### Cycle 2.2：场景型审计 Skill 不被通用 JWT 抢占

**RED**

- `Java JWT source audit` Top 1 为 java-auth-config-audit。
- `PHP JWT configuration audit` Top 1 为 php-auth-config-audit。

**GREEN**

- 增加 name+tags concept coverage 排序键。

### Cycle 2.3：SQL Injection canonical methodology

**RED**

- 构造 sqlmap、judge、attack-chain 和 sql-injection-methodology。
- `SQL injection` Top 1 为 canonical methodology。

**GREEN**

- 支持复合 concept 对 normalized name 的完整命中。

### Cycle 2.4：Linux privilege escalation

**RED**

- `privilege escalation linux` 优先 post-exploit-linux，而不是 aws-iam-privesc。

**GREEN**

- 增加 anchor name coverage 后的 name+tags total coverage。

### Cycle 2.5：cutoff 保留 canonical identity

**RED**

- canonical name 命中但 raw BM25 低于普通长文档时不得被 cutoff 删除。
- 仅正文弱命中的尾部资源仍会被删除。

**GREEN**

- 将 cutoff 与 canonical ranking 收口到显式 pipeline。

### Cycle 2.6：稳定排序与轻量候选

**RED**

- 相同 score/coverage 使用 stable ID 稳定排序。
- 搜索摘要不依赖完整 body。

**GREEN**

- 添加稳定尾键和 lightweight candidate projection。

Slice 2 门禁：`go test ./internal/search ./internal/mcp`。

## Slice 3：公共接口、真实 corpus 与性能

### Cycle 3.1：MCP 搜索版本

**RED**

- `Service.Search` 返回 `search_version=security-concepts-v1`。
- 旧字段和 stable ID 保持不变。

**GREEN**

- 增加向后兼容顶层字段。

### Cycle 3.2：REST 与 MCP 排序一致

**RED**

- 相同 query/type/visibility 下，REST 与 MCP Top IDs 一致。

**GREEN**

- REST 复用同一 search pipeline，只保留显式 visibility/policy 差异。

### Cycle 3.3：真实 corpus golden

**RED**

- 新增真实 runtime/builtin corpus golden harness。
- 先确认 JWT/SQL canonical 断言在旧实现失败。

**GREEN**

- 只扩充由失败驱动的 concept aliases/ranking，不硬编码 Resource ID 到生产代码。

### Cycle 3.4：无回归查询集

- File Upload、OAuth、Java Deserialization、SSRF Cloud Metadata。
- disabled/type/category/source/vuln filters。
- empty query list 行为。
- no_match 不缩短查询。

### Cycle 3.5：性能

- 对代表性查询运行重复 benchmark。
- p95 <= 20ms 且 <= legacy 2x。
- 候选上限和响应大小有界。

Slice 3 门禁：`go test ./...`、`python3 -m pytest build/test_build_index.py -q`、真实 MCP curl。

## Slice 4：PoJun durable integration

### Cycle 4.1：新 resolver version 不复用旧 binding

**RED**

- 旧 `fts-v1` ready resolution 存在时，新策略必须 claim 新 resolution。

**GREEN**

- `RESOLVER_VERSION = "fts-concepts-v2"`。

### Cycle 4.2：持久化 search version 可观测性

**RED**

- Resolver trace 包含 context1337 `search_version`。
- 缺失版本明确记录 legacy，不影响兼容节点搜索。

**GREEN**

- 透传顶层版本到 trace；不改变 binding digest/Resource ID 合约。

### Cycle 4.3：真实 JWT 跨组件闭环

**RED**

- 通过 Pojun Worker knowledge proxy 调用真实 context1337。
- `JWT algorithm confusion` 绑定包含 `jwt-attack-methodology`，旧错误 Top 2 不再占满。

**GREEN**

- 只做必要适配，不在 Pojun 添加 fallback/reranker。

### Cycle 4.4：OODA/session 无回归

- Resolver 完成前不 acquire Explore。
- metadata 冻结新 Resource ID/search digest。
- Agent `knowledge_resource_loaded`。
- 每个 Explore 单 execution/session/attempt。
- knowledge trace 不推进 Reason trigger。

Slice 4 门禁：PoJun knowledge/Reason/Review/Server 定向套件和 Dispatcher 非 integration 扩大回归。

## 发布顺序

1. context1337 完成 Slice 1–3、版本升级、发布节点。
2. 验证所有节点返回 `search_version=security-concepts-v1`。
3. PoJun 完成 Slice 4 并提升 resolver version。
4. 创建真实 JWT 项目验收。
5. 观察 no_match、Top Resource、load 消费率和 Explore 成功率。

## 回滚

- context1337 保留 legacy ranker 开关或可直接回滚二进制；不需要 DB 回滚。
- PoJun 不改变 query 或执行 fallback。
- 若 context1337 回滚，PoJun 新 resolution 会记录 legacy search version，便于识别混合节点。
