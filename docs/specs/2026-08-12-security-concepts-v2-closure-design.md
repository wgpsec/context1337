# Security Concepts v2 收口修复设计规范

## 状态

- 日期：2026-08-12
- 状态：前三项已按独立 TDD 实施并验证；第四项及发布闭环待实施
- 影响仓库：`context1337`、`AboutSecurity`、`pojun`
- 前置规范：`docs/specs/2026-08-11-security-concepts-v2-design.md`
- 原则：修复既有 v2 契约，不引入第二套搜索、统计或存储系统

## 摘要

Security Concepts v2 的主体方向成立，Go FTS finalizer、runtime FTS 原地迁移、结构化
`query_too_complex`、默认 vuln 排除和 PoJun Review 查询约束均已具备。但代码审计发现四个
尚未闭环的问题：

1. `name` 和 `category` 没有经过权威 tokenizer，索引与查询契约仍不完全一致；
2. focused retry 仅覆盖超限查询，且 `Anchor` 混合表达 identity 与 method，不能稳定拆分一般
   multi-topic no-match；
3. Context1337 新增的 complexity rejection 指标在 PoJun 采集、持久化和页面中被丢弃；
4. 新 AboutSecurity corpus 尚未进入固定 revision 的 release image，现有 builtin 版本升级还会
   删除整个 runtime DB，无法安全发布内容更新。

本规范给出四项最小修复及其测试、发布和回滚顺序。四项完成前，v2 可以继续本地验证，但不得
宣称新 corpus 已完成可复现发布闭环。

本轮只实施问题一至三。问题四继续采用本规范中的简单 source-owned 删除语义，不额外引入永久
tombstone/override 表；runtime builtin merge、AboutSecurity revision pin 和 release image 发布流程
均未在本轮改动。

## 不变边界

- Go `internal/tokenize` 仍是唯一 FTS tokenizer；Python 不实现等价分词器。
- raw `resources` 保留可读原文，只有 `resources_fts` 保存 tokenized text。
- focused query 的组间语义仍为 `AND`，不增加宽泛 OR fallback、LLM query rewrite 或 embedding。
- `query_too_complex` 和 `no_match` 均为成功的 MCP tool response，不变成 execution error。
- type 省略时继续排除 `vuln`，不在服务端自动执行第二次 vuln search。
- PoJun 仅消费聚合 usage，不进入 Context1337 搜索执行路径，不影响 Dispatcher、Worker 或 OODA。
- 不为通过测试伪造漏洞、产品、PoC、默认口令或组合攻击链内容。

## 问题一：FTS 字段契约不完整

### 现状与风险

`internal/fts.Replace` 当前仅对 `description`、`tags` 和 `body` 调用
`TokenizeToString`，`name` 与 `category` 以原文写入。查询侧却始终使用 Go tokenizer 编译 FTS
atoms。因此，仅存在于中文名称或中文分类中的连续词可能无法命中。

现有“积木报表”测试不能覆盖该风险，因为相同文本也出现在 description，测试即使在 name 未
tokenize 时仍可能通过。

### 决策

`fts.Replace` 必须对所有实际 FTS columns 使用同一个函数：

```text
name, description, tags, category, body
  -> tokenize.TokenizeToString
  -> resources_fts
```

现阶段 aliases 仍按上游内容模型写入 `tags`，因此也自然进入同一 tokenizer；本修复不增加
独立 aliases column。raw `resources` 内容、detail API 和 stable identity 均不改变。

build finalizer、runtime migration、team/custom/nuclei 写入和普通 `InsertResource` 必须继续只
调用同一个 `fts.Replace`，不得出现字段级旁路。

### TDD 验收

1. RED：创建中文短语只存在于 `name`、其他字段均不包含该短语的资源，公共 `Search` 无法命中。
2. GREEN：tokenize `Name` 后命中，detail 仍返回原始名称。
3. RED/GREEN：用独立资源证明中文短语只存在于 `category` 时也能命中。
4. 验证 description/tags/body、英文名称、CVE ID、路径型名称和既有 canonical ranking 不回归。
5. FTS contract version 从当前值升级，确保已经写入旧 v2 索引的 runtime DB 会执行一次重建；
   不得沿用相同 version 让错误索引长期存留。

## 问题二：Multi-topic retry 语义不完整

### 现状与风险

当前 `retry_queries` 只在 planner 抛出 `QueryComplexityError` 时生成。未超过 8 groups/48 atoms
但包含多个方法主题且没有组合 Skill 的查询，会得到普通 `no_match`，调用方无法区分“知识库
缺内容”和“请求应拆成多次 focused search”。

同时，`SecurityConcept.Anchor` 当前同时标记产品/技术身份和漏洞方法。例如 `php`、`linux`、
`sql_injection`、`privilege_escalation` 都是 Anchor。retry planner 会把所有 Anchor 放入每一条
retry，无法满足以下原 v2 约束：

- 保留产品 identity；
- 每条 retry 最多包含一个主要漏洞或方法概念。

### 决策

用一个有类型的 concept role 替代布尔 `Anchor`：

```text
identity  产品、框架或必须保留的技术身份
topic     漏洞类型、攻击方法或独立调查主题
context   可随对应 topic 保留的限定词
```

`QueryGroup` 携带 role。未知 exact group 默认是 `context`，不能被猜成产品或漏洞方法。静态 concept
registry 的每组 aliases 上限仍为 6，并由单元测试验证 alias 规范化后唯一、跨 concept 不冲突。

确定性 retry 规则：

1. 保留所有已识别的 `identity` groups；
2. 每条 retry 只加入一个 `topic` group；
3. `context` 按原输入顺序、在每条总计最多 4 groups 的范围内分配；
4. 至少识别到两个 `topic` 时，原查询属于可安全拆分的 multi-topic query；
5. 无 identity 时允许按单个 topic 返回 focused retries，但不得猜测或新增 identity；
6. 无法可靠识别两个 topic 时保持 `no_match`，只返回原有 broader/vuln hint；
7. retry 顺序完全由原 group 顺序决定，且每条必须能再次通过 `PlanQuery`；
8. 如果原查询真实命中经过维护的组合 Skill，保持 `matched`，不返回 retries。

`SearchResult.status` 不增加新的枚举：

- 超限：`query_too_complex` + `retry_queries`；
- 未超限 multi-topic 且无匹配：`no_match` + `retry_queries` + 明确拆分 hint；
- 普通内容缺口：`no_match`，无伪造 retries；
- 真实组合 Skill：`matched`。

该方案只补充返回建议，不在 Context1337 内自动执行 retry。

### TDD 验收

1. session/identity 存在且 query 可命中时，搜索结果与 v2 当前行为一致。
2. 构造未超限、含 identity 和两个 topic、没有组合 Skill 的查询，返回两条 focused retries。
3. 每条 retry 保留 identity、最多一个 topic、最多 4 groups，并可由 `PlanQuery` 执行。
4. 相同输入重复调用返回完全相同的 retry 内容和顺序。
5. 没有可靠 topic 分类的普通 no-match 不生成猜测性 retries。
6. `php 反序列化 文件包含 日志投毒`、`yii 反序列化 csrf 伪造`：有真实组合 Skill 时
   `matched`；移除该 fixture 后返回 focused retries。
7. SystemManage、Learun/力软、JWT canonical ranking、vuln hint 和 FTS escaping 保持不变。
8. registry 中任一 concept 超过 6 aliases、alias 重复或跨 concept 冲突时测试失败。

## 问题三：PoJun 丢弃 Complexity Analytics

### 现状与风险

Context1337 usage v2 已输出：

```text
search.rejected_complexity_total
search.queries[].rejected_complexity
```

PoJun 的 scalar paths、query counters、`context1337_usage_search_hourly`、聚合 API 和 Knowledge
页面均未接收该字段。结果是 complexity rejection 在跨进程采集时消失，运营者会低估搜索需求，
也无法判断应补 corpus 还是应优化调用方 query。

### 决策

PoJun 端到端增加 `rejected_complexity`，不把它并入 zero result 或 execution error：

```text
Context1337 cumulative snapshot
  -> scalar/query delta
  -> hourly SQLite aggregate
  -> /knowledge/usage
  -> Usage Analysis
```

具体变更：

- `_SCALAR_PATHS` 增加 `rejected_complexity`；
- `_QUERY_COUNTERS` 增加 `rejected_complexity`；
- `context1337_usage_search_hourly` 增加
  `rejected_complexity INTEGER NOT NULL DEFAULT 0`；
- 通过幂等 schema migration 为既有数据库补列，不重建或清空历史表；
- totals、trend 和 query demand 返回该字段；
- API 增加 `complexity_rejections` 列表，按 rejection 次数、calls、query 稳定排序；
- UI 增加 Complexity Rejections 指标与列表/列，明确与 Content Gaps、Search Errors 分开；
- 旧 Context1337 snapshot 缺字段时按 0 处理，保持滚动升级兼容。

该字段只增加统计可见性，不改变 Context1337 搜索结果、PoJun Review、Knowledge resolver 或调度。

### TDD 验收

1. 旧 snapshot 无新字段时正常采集，rejected complexity 为 0。
2. 新 snapshot 的 scalar 与 query rejection 能正确计算首次、后续、重复快照和进程重启 delta。
3. rejection 不增加 `zero_results`、`errors` 或 `matched`。
4. 从旧 PoJun DB 启动时幂等增加列并保留已有 hourly/query 数据。
5. API totals、trend、query demand 和 `complexity_rejections` 返回正确值与稳定排序。
6. Super Admin 页面展示独立指标；其他角色权限、空/陈旧/失败状态保持不变。
7. Context1337 v1/旧版本与 PoJun 新版本可以按任意顺序滚动升级。

## 问题四：Corpus 发布与 Runtime-owned State 冲突

### 现状与风险

候选 corpus golden tests 依赖 `CONTEXT1337_CORPUS_DB`。未设置时普通 `go test ./...` 会 skip，
因此测试代码存在并不证明 release image 已包含目标资源。当前 release workflow 仍固定旧的
`ABOUTSECURITY_COMMIT`，Docker 构建也未完成，新的 AboutSecurity 内容尚未进入发布产物。

更严重的是，`InitRuntime` 检测到 `builtin_version` 变化时会删除 `runtime.db` 并重新复制
`builtin.db`。该路径会丢失 numeric row ID、builtin enabled override 以及 custom/team/nuclei
等 runtime-owned 状态，与 v2 的升级和回滚约束冲突。

### 决策：原地同步 Builtin Source

首次启动仍可直接复制 finalized `builtin.db`。已存在 runtime DB 时禁止因 builtin version 变化
删除数据库，改为单事务、按 source 同步：

1. 读取 finalized builtin DB 的 raw resources 与 `builtin_version`；
2. 以 `(type, name, source)` 为 canonical key，且本流程只管理 `source='builtin'`；
3. 已存在 builtin key：`UPDATE` 内容字段，保留 runtime `id` 和 `enabled`；
4. 新 builtin key：普通 `INSERT`，分配新的 runtime numeric ID；
5. 旧 runtime builtin key 已不在新 builtin 中：删除该 builtin row；
6. `source!='builtin'` 的 custom/team/nuclei rows、ID 与 enabled 完全不触碰；
7. 在同一 transaction 内重建 FTS，并在成功后写入新的 `builtin_version` 和 FTS contract version；
8. 任一步失败则回滚，继续保留升级前 runtime DB；禁止先 `os.Remove`；
9. 禁止使用 `INSERT OR REPLACE` 更新既有行，避免 SQLite 更换 numeric ID。

这里不引入第二个 runtime DB、影子表或双写系统。约 5,000 级资源可在启动迁移中一次读取；若未来
corpus 规模显著增长，再基于实际指标设计流式同步，不作为本次实体。

### 内容与 Release 门禁

AboutSecurity 内容必须先独立 commit，并取得不可变 commit SHA。Context1337 release workflow
随后更新 `ABOUTSECURITY_COMMIT` pin，不允许依赖本地脏工作区或浮动分支。

candidate corpus 验证必须成为 image contract 的强制测试：

- 从待发布镜像实际启动服务；
- 复放规范中的 19 条矩阵和 P0 queries；
- 校验 status、Top stable IDs、unsupported no-match、vuln exclusion 与 focused retries；
- 测试不得因缺少 `CONTEXT1337_CORPUS_DB` 而 skip；
- 校验镜像内记录的 AboutSecurity commit 与 workflow pin 一致；
- 保留现有 nuclei revision、目录覆盖和 FTS contract 检查。

Docker Hub/GCR metadata timeout 属于构建环境失败，可以重试或使用可信镜像缓存，但在真实 candidate
image 构建和 contract tests 通过前，不得把它记为 release verification 已完成。

### TDD 验收

1. 旧 runtime 中一个 builtin row 被禁用；升级同 key 内容后，其 numeric ID 和 disabled 状态保留。
2. 新 builtin row 被加入，已删除的 builtin row 被移除。
3. custom/team/nuclei rows 的内容、ID、enabled 和 stable identity 全部保留。
4. 同一 builtin version 重启不重复迁移；升级中途失败完整回滚。
5. 迁移后所有 FTS rowid 与 resources.id 对齐，新旧资源均可搜索。
6. release image contract 从镜像自身验证固定 AboutSecurity revision 和完整 query matrix，无条件执行。
7. fresh install 与 existing-runtime upgrade 两条路径均通过真实 image smoke test。

## 实施顺序

按以下 tracer bullets 独立完成，不把四项混成一次大改：

1. **Context1337 FTS contract**：先补 name/category RED tests，再修改 `fts.Replace` 并升级 contract
   version；运行 Go 全量、race、vet 和 builder tests。
2. **Context1337 retry semantics**：先补未超限 multi-topic no-match RED test，再引入 concept role 和
   deterministic retry；复放 canonical ranking 与 P0 planner tests。
3. **PoJun analytics**：先用新 snapshot 建立 ingestion RED test，再补 schema、聚合/API，最后补 UI；
   运行 Server 定向测试和 frontend component tests。
4. **Runtime builtin merge**：先建立旧 runtime 升级 fixture，证明当前 delete/rebuild 会丢状态；再实现
   原地同步和事务回滚。
5. **Corpus release**：提交 AboutSecurity 内容、更新固定 pin、构建 candidate image并执行无 skip 的
   release contract matrix。

前 1 至 3 项互不依赖，可分别审查；第 4 项必须在第 5 项之前完成。PoJun 可以在 Context1337
发布前部署，因为缺失的新 usage 字段会按 0 兼容。

## 本轮实施结果

### 1. Context1337 FTS contract

- 先通过公共 `InsertResource` + `Search` 分别建立“中文文本只存在于 name”和“只存在于
  category”的 RED 用例，再统一交由 `fts.Replace` 对五个 FTS 字段执行权威 tokenizer。
- FTS contract 从 `go-security-tokenizer-v2` 升级到 `go-security-tokenizer-v3`，runtime migration、
  CLI finalizer 和 release image contract 均校验新版本。
- raw `resources` 内容、stable identity 和 detail 返回值未改变。

### 2. Context1337 multi-topic retries

- 先建立未超限 multi-topic `no_match` 的 RED 用例，再将 concept 分类为 `identity`、`topic`、
  `context`，由确定性 planner 生成 focused retries。
- 已覆盖带 identity、无 identity、真实组合 Skill、未知主题、四 identity 耗尽 group budget，以及
  aliases 数量、空值和规范化冲突边界。
- 返回值仅补充 `status`、`retry_queries` 和 hint；Context1337 不自动执行 retry，普通 matched、
  vuln 排除和 ranking 语义保持不变。

### 3. PoJun complexity analytics

- 先建立 cumulative snapshot delta 的 RED 用例，再补齐 scalar/query ingestion、SQLite schema migration、
  hourly aggregate、API 和 Super Admin Usage Analysis 页面。
- `rejected_complexity` 独立于 matched、zero result 和 error；旧 snapshot 缺字段按 0 处理，旧数据库
  通过幂等加列保留历史数据。
- 中、英、繁三套 i18n 已同步，页面将 Complexity Rejections 与 Content Gaps、Search Errors 分开展示。

### 验证证据

Context1337：

```text
go test ./...                         PASS
go test -race ./...                   PASS
go vet ./...                          PASS
两种 Python builder 入口              22 passed / 22 passed
representative runtime corpus p95     5.03ms（门禁 <= 20ms）
```

PoJun：

```text
tests/test_server/test_context1337_usage.py    12 passed
Knowledge frontend component tests             8 passed
changed Server files py_compile                 PASS
frontend production build                      PASS
```

`npm run check:i18n` 仍被并行开发中的 `ModelAccess.svelte` 既有硬编码文本阻断；本轮新增的 usage
i18n keys 未出现在错误列表中。两仓库 `git diff --check` 均通过。

问题四仍为待实施项，因此本轮不满足下文的完整 release 完成定义，也未构建或发布 candidate image。

## 完整验证门禁

Context1337：

```bash
go test ./...
go test -race ./...
go vet ./...
python3 -m unittest build.test_build_index -v
python3 build/test_build_index.py -v
make test-release-image IMAGE=<candidate>
```

PoJun：

```bash
python3 -m pytest tests/test_server/test_context1337_usage.py -v
cd frontend && npm test -- --run src/components/Admin/Knowledge.test.js
```

最终验收还必须记录：

- candidate image digest；
- Context1337、AboutSecurity、nuclei-templates 三个不可变 revision；
- fresh install 与 existing-runtime upgrade 结果；
- query matrix 的 status 和 Top stable IDs；
- representative search p95，要求不高于 20ms；
- 所有被 skip 的测试及原因，release contract 不允许 skip。

## 发布与回滚

发布顺序：

1. 先发布兼容新字段的 PoJun analytics；
2. 合入 Context1337 搜索与 runtime merge 修复；
3. 合入并固定 AboutSecurity revision；
4. 构建、验证并发布 Context1337 candidate；
5. canary 使用现有 runtime volume 升级，核对 disabled/custom/team/nuclei 和 query matrix；
6. 再替换其余实例。

回滚 binary/image 时保留 runtime volume。由于升级为原地事务同步，不需要恢复整库备份才能回滚；
但回滚到仍采用 delete/rebuild 的旧 binary 前，必须避免让旧 binary 对较新 `builtin_version` 执行启动
迁移。最稳妥的回滚是回到包含原地 merge 逻辑、但 pin 回旧 AboutSecurity revision 的兼容镜像。

## 完成定义

只有同时满足以下条件才能把 Security Concepts v2 标记为 released：

- 所有 FTS 字段使用同一 tokenizer，旧 runtime 已通过新 contract version 自动重建；
- 超限与可识别 multi-topic no-match 都返回确定性、可执行的 focused retries；
- PoJun 完整保存并展示 rejected complexity，且不污染 gap/error；
- builtin 内容升级不删除 runtime-owned 状态；
- AboutSecurity 固定 revision 已进入真实 candidate image；
- release image query matrix、升级 smoke、race/vet/test 和性能门禁全部通过。
