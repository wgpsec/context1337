# Security Concept Search 设计规范

## 状态

- 日期：2026-07-17
- 状态：Implemented
- 影响仓库：`context1337`、`pojun`
- 兼容目标：context1337 0.7.x、PoJun 3.1.5

## 实施结果

- context1337 搜索契约版本为 `security-concepts-v1`，应用版本为 `0.7.4`。
- PoJun Resolver 契约版本为 `fts-concepts-v2`；PoJun 产品版本保持 `3.1.5`。
- 查询只执行一次完整 FTS expression；没有 category 转发、删词、缩短查询或 JWT fallback。
- canonical 排序以 anchor/name/name+tags coverage、BM25、stable Resource ID 为确定性排序键。
- MCP 与 REST 都暴露 `search_version`；PoJun 在 durable trace 中记录单一版本、`legacy` 或 `mixed`。
- 未修改 SQLite schema、runtime DB、OODA generation、Intent acquire、execution 或 Agent session 生命周期。

## 背景

PoJun Intent Knowledge Resolver 已能在 Explore 前确定性调用 context1337、持久化稳定 Resource ID，并要求 Agent 通过 `get_security_detail` 消费推荐 Skill。真实项目 `proj_1289` 证明调度、绑定和消费链路成立，但检索结果没有推荐最相关的 JWT 方法论：

- `JWT algorithm confusion` 返回 `php-auth-config-audit`、`judge-pentest`；
- `JWT none algorithm bypass` 返回 `java-auth-config-audit` 等；
- `JWT authentication bypass` 返回 `cookie-analysis`、`java-auth-config-audit`；
- `absec://builtin/skill/jwt-attack-methodology` 未进入 PoJun 前两个候选。

直接查询表明 `JWT 算法混淆` 和 `JWT none algorithm` 可以将 JWT 方法论排到第一，因此问题位于 context1337 的跨语言概念召回和 canonical resource 排序，而不是 PoJun 的 category、fallback、OODA 或 session 逻辑。

## 当前行为

### 查询链路

```text
query
  -> Go Tokenize
  -> every token joined with AND
  -> SQLite FTS5 candidates
  -> BM25(name=10, description=5, tags=5, category=2, body=1)
  -> MCP relevance cutoff
  -> optional cross-type diversification
  -> caller limit
```

### 已确认缺陷

1. **跨语言等价词缺失**：英文 `confusion` 不匹配中文 `混淆`，正确资源在 BM25 前就被排除。
2. **canonical identity 不参与排序**：`SQL injection` 的 canonical methodology 排在 sqlmap、综合攻击链和 judge 之后。
3. **英文安全词按子串匹配**：现有 `strings.Index` 没有 ASCII 词边界，短术语可能污染普通单词。
4. **分词契约分裂**：builtin 索引使用 Python/jieba，runtime/team/custom 使用 Go tokenizer，二者没有共享概念表。
5. **测试只验证机械搜索**：没有 `query -> expected stable Resource ID` 的 relevance golden suite。
6. **搜索版本不可观测**：PoJun durable resolution 无法区分旧检索策略和新检索策略。

## 目标

1. 英文、中文和常见安全缩写查询能召回语义等价的真实资源。
2. 与查询主题同名或在名称中覆盖核心概念的 canonical Skill 优先于正文偶然高频命中的综合资料。
3. 保持确定性、可审计、无 LLM、无向量服务依赖。
4. 不删除查询概念，不从多词查询退化到单一宽泛词，不实现 PoJun 侧 fallback。
5. 不修改现有 FTS schema，不要求本次发布重建 runtime DB。
6. 保持 type/category/source/visibility、稳定 ID、MCP tool 和 REST API 的向后兼容。
7. 不改变 PoJun OODA generation、Intent acquire、execution、Agent session 或 continuation 语义。

## 非目标

- 不引入 LLM reranker。
- 不引入 embedding 或向量数据库。
- 不让模型生成、猜测或改写 Resource ID。
- 不自动删除 `bypass`、`audit` 等查询词来扩大召回。
- 不在无结果时二次执行缩短后的查询。
- 不在本次发布中迁移或重建 builtin/runtime FTS schema。
- 不重新设计 AboutSecurity 内容格式。

## 术语

- **Security Concept**：一个稳定安全语义，如 `jwt`、`jwt_algorithm_confusion`、`privilege_escalation`。
- **Alias**：同一 Concept 的语言、缩写或规范写法，如 `算法混淆` 与 `algorithm confusion`。
- **Concept Group**：查询中的一个必选语义组；组内 aliases 为 OR，组间为 AND。
- **Anchor**：可用于识别主题资源身份的 Concept，例如 JWT、OAuth、SQL Injection、Java、Linux。
- **Canonical Skill**：名称或标签明确代表查询主题的首选方法论资源。
- **Exact token**：未被 Concept Registry 识别、必须原样匹配的查询词。

## 核心设计

### 1. Security Concept Registry

新增版本化 registry，作为查询概念、别名和 anchor 属性的唯一来源。首版至少覆盖真实 golden queries：

```yaml
version: security-concepts-v1
concepts:
  - id: jwt
    aliases: [JWT, JSON Web Token]
    anchor: true
  - id: algorithm
    aliases: [algorithm, 算法]
  - id: confusion
    aliases: [confusion, 混淆]
  - id: bypass
    aliases: [bypass, 绕过]
  - id: privilege_escalation
    aliases: [privilege escalation, privesc, 权限提升, 提权]
    anchor: true
```

约束：

- Concept ID 唯一；alias 在规范化后不得冲突到多个 Concept。
- ASCII alias 只在词边界匹配；CJK alias 可按完整连续文本匹配。
- `-`、`_`、空格在 alias 规范化时等价。
- 使用 longest-match，优先识别完整复合概念。
- registry 有显式版本；查询结果暴露使用的版本。
- 初版 registry 保持小而可审计，只由 golden failure 驱动扩充。

### 2. Query Plan

新增公共查询规划接口：

```go
type QueryPlan struct {
    RawQuery      string
    Groups        []ConceptGroup
    FTSExpression string
    Version       string
}

func PlanQuery(raw string) (QueryPlan, error)
```

规划规则：

1. 对 raw query 做 Unicode lower-case 和分隔符规范化，但保留原始值用于审计。
2. 使用 registry longest-match 提取 concepts。
3. 未识别词生成 exact group。
4. 每个 group 内 alias alternatives 使用 OR。
5. 不同 group 使用 AND。
6. 不删除 group；没有第二次查询。

示例：

```text
JWT algorithm confusion

=> ("jwt" OR "json web token")
   AND ("algorithm" OR "算法")
   AND ("confusion" OR "混淆")
```

```text
JWT none algorithm bypass

=> ("jwt" OR "json web token")
   AND "none"
   AND ("algorithm" OR "算法")
   AND ("bypass" OR "绕过")
```

这里的 alias expansion 属于一次查询内的语义等价归一化，不是 fallback。

### 3. 安全与复杂度限制

- raw query 最大 256 bytes；PoJun 仍保持自己的 160 字符限制。
- 最多 8 个 Concept/Exact groups。
- 每个 group 最多 6 个 alias alternatives。
- 编译后最多 48 个原子 FTS token。
- 所有 token 通过结构化 builder 转义；调用方不能直接注入 FTS 运算符。
- 超限返回明确错误，不静默删词。
- 空 query 保持现有 list 语义，不进入 Query Planner。

### 4. Candidate Retrieval

- 所有候选仍必须满足完整 QueryPlan。
- 保持 enabled/type/category/source/severity/product 过滤。
- `type=vuln` 首版保持现有 BM25/pagination 行为，避免扩大风险。
- Skill/dict/payload 查询使用有界 candidate window；不得批量加载完整 body。
- 候选 projection 只包含排序和摘要需要的字段。
- raw BM25 score 继续保留，作为最终排序的后置特征。

### 5. Canonical Ranking

候选集合不变，只做纯函数确定性排序：

```go
func RankCandidates(plan QueryPlan, candidates []SearchResult) []SearchResult
```

排序键：

1. anchor concept 在 normalized resource name 中的完整命中数，降序；
2. 全部 query group 在 normalized resource name 中的完整命中数，降序；
3. query group 在 name + tags 中的覆盖数，降序；
4. raw BM25 score，升序；
5. stable Resource ID，升序。

未识别 exact token 也参与 coverage，但不获得跨语言 alias。

期望：

- `JWT authentication bypass`：JWT methodology 优先于 cookie-analysis；
- `Java JWT source audit`：Java auth audit 优先于 JWT methodology；
- `SQL injection`：sql-injection-methodology 优先于 sqlmap-advanced；
- `privilege escalation linux`：post-exploit-linux 优先于 aws-iam-privesc。

### 6. Relevance Cutoff

现有 cutoff 假设结果按 BM25 排序。新流程调整为：

```text
FTS candidates
  -> raw BM25 cutoff
     OR preserve explicit name/anchor matches
  -> canonical ranking
  -> diversify when type is omitted
  -> pagination/limit
```

要求：

- 明确 name/anchor 命中不能只因正文 BM25 较弱被提前删除。
- 仅正文偶然命中的长尾候选仍应被 cutoff。
- total、offset、limit 与最终可分页结果一致。

### 7. MCP 与 REST

MCP 和 REST 复用相同的 QueryPlan、candidate retrieval 和 canonical ranking。入口差异必须成为显式 policy：

- MCP 默认 `VisibilityEnabledOnly`；
- 管理 REST 可使用 All/DisabledOnly；
- type 省略时 MCP 可启用 diversify；
- 管理 REST 是否 cutoff 由显式选项控制，不再隐式绕开统一排序。

搜索响应新增向后兼容顶层字段：

```json
{
  "search_version": "security-concepts-v1",
  "total": 3,
  "offset": 0,
  "limit": 10,
  "items": []
}
```

不向普通 MCP 响应暴露冗长 query plan。benchmark/debug 记录 query digest、version、alias 使用、候选数量和 Top IDs。

## PoJun 集成

context1337 所有节点升级后：

1. PoJun `RESOLVER_VERSION` 从 `fts-v1` 升为 `fts-concepts-v2`，避免旧 ready binding 被复用。
2. 搜索响应中的 `search_version` 写入 resolution trace；缺失版本时按 legacy 可观测，不伪装成新策略。
3. 保持每个 Intent 最多 2 条 query。
4. 保持不转发 model category。
5. 保持每条 query 原样调用一次，不执行 fallback。
6. 保持每条 query 最多消费 2 个候选、每个 Intent 最多 3 个去重资源。
7. 不修改 execution/session/OODA 状态机。

## 数据与迁移

首版只修改 query planning 与 ranking：

- 不修改 SQLite schema；
- 不改变 builtin_version；
- 不重建 runtime.db；
- 不影响 enabled 状态、custom/team/nuclei 资源；
- 不改变 stable Resource ID。

后续可让 registry 生成 Go SecurityTerms 与 Python jieba dictionary，但必须单独设计 runtime 数据保留和 reindex 迁移，不纳入本次核心发布。

## 可观测性

最小指标：

- `search_version`；
- query digest；
- concept group 数；
- alias expansion 是否发生；
- FTS 候选数、cutoff 后候选数；
- Top Resource IDs；
- duration_ms；
- no_match 比例。

PoJun 侧继续观察：

- matched/no_match/unavailable；
- recommended Resource IDs；
- `knowledge_resource_loaded` 消费率；
- 推荐后 Explore 成功率；
- OODA generation 与 session 数量。

## 验收标准

### Relevance golden

- `JWT algorithm confusion` -> `jwt-attack-methodology` Top 1；
- `JWT none algorithm bypass` -> `jwt-attack-methodology` Top 1；
- `JWT authentication bypass` -> `jwt-attack-methodology` Top 1；
- `JWT 算法混淆` -> `jwt-attack-methodology` Top 1；
- `SQL injection` -> `sql-injection-methodology` Top 1；
- `file upload webshell` -> `file-upload-methodology` Top 1；
- `OAuth redirect URI` -> `oauth-sso-attack` Top 1；
- `Java deserialization` -> `java-deserialization-methodology` Top 1；
- `Java JWT source audit` 不得被 JWT methodology 错误抢占；
- `PHP JWT configuration audit` 不得被 JWT methodology 错误抢占。

### 安全与兼容

- `source audit` 不产生 `rce` token；
- 特殊字符不能注入 FTS 运算符；
- no_match 不执行缩短查询；
- disabled/type/category/source/vuln 过滤无回归；
- 同一 DB、query、filters 的结果顺序稳定；
- Go、Python build、MCP、REST 测试通过。

### 性能

- 当前约 3,500 资源规模下，代表性查询 p95 <= 20ms；
- 不高于旧实现 p95 的 2 倍；
- 单次查询内存不加载所有匹配资源 body。

### PoJun E2E

- Reason 每个 Intent 最多 2 条 query、category 为空；
- resolution 为新 resolver/search version；
- metadata 包含 `jwt-attack-methodology`；
- Agent 产生对应 `knowledge_resource_loaded`；
- Explore 只有一个 execution/session/attempt；
- `act_generation == reason_consumed_generation`；
- 不产生 knowledge trace 驱动的 Reason trigger。

## 发布与回滚

1. 先发布 context1337，保留 legacy feature flag 或可回滚二进制。
2. 在所有 Worker Service 节点确认 `search_version=security-concepts-v1`。
3. 运行 golden 与真实 JWT smoke。
4. 再发布 PoJun `RESOLVER_VERSION` bump。
5. 若 precision 指标回退，回滚 context1337 ranker；PoJun 不做查询 fallback。
