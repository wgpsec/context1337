# Security Concepts v2 搜索修复设计规范

## 状态

- 日期：2026-08-11
- 状态：Implemented locally; release pending
- 搜索契约：`security-concepts-v2`
- 影响仓库：`context1337`、`AboutSecurity`、`pojun`
- 输入基线：生产 `context1337 v0.7.6` usage 快照与
  `/tmp/context1337-v076-search-gaps-handoff-2026-08-11.md`

## 摘要

本设计修复三类被生产查询同时暴露的问题：

1. builtin 索引、runtime 写入和查询使用不同分词器，导致已有内容无法召回；
2. Query Planner 把中文二元词误当成 Security Concept，正常产品查询触发 8 组上限；
3. 内容缺口、filter 误用和多主题查询都被记录成同一种 zero result，诱导维护者重复造数据。

v2 先统一索引契约，再分离语义规划和 FTS 编译，最后补真实内容。Focused query
继续使用组间 `AND`，不引入 LLM、embedding、静默删词或宽泛 OR fallback。

## 已验证基线

在隔离的 v0.7.6 服务和 builtin corpus 上已复现：

- `asp.net mvc 通用权限管理系统 systemmanage sql注入` 产生 13 个 token，超过 8 组；
- `learun 力软 通用权限管理系统` 产生 9 个 token，超过 8 组；
- handoff 中 19 条真实查询均返回 zero result；
- `积木报表` 已存在于 `CVE-2023-1454` 原文，但查询侧要求
  `积木 AND 木报 AND 报表`，Python/jieba 索引只有 `积木 报表`；
- `密码字典 弱口令 常用密码` 的三个概念已存在于字典元数据，但相同分词偏差导致零结果；
- `queryfieldbysql` 已存在于 `CVE-2023-4450`，但无 type 查询按现有策略排除 vuln。

## 现有根因

### 分词契约分裂

- release builtin DB：Python `jieba.cut_for_search`；
- team/custom/nuclei runtime 写入：Go `internal/tokenize`；
- query：Go `internal/tokenize`；
- Security Concept aliases：直接作为 FTS quoted token，不先编译成索引原子词。

因此，向 AboutSecurity 正文或 tags 添加中文 alias 并不保证可召回。

### 语义组与索引词混淆

`PlanQuery` 当前先调用底层 tokenizer，再把每个 token 包装成 `QueryGroup`。中文未知短语
会产生重叠二元词，每个二元词均消耗一个 concept 名额。复杂度限制本身合理，但计数对象错误。

### 结果语义过载

当前 `total=0` 同时可能表示：

- corpus 确实没有内容；
- 内容存在但分词不兼容；
- type/filter 排除了内容；
- query 含多个不应由单条资源同时满足的主题；
- query 超过 planner 复杂度限制并执行失败。

这些 outcome 必须在接口和 usage 中分开。

## 目标

1. 相同原文在 builtin、team、custom、nuclei 中产生相同的 FTS 原子词。
2. Query Planner 以语义组计数，FTS compiler 以原子词限制复杂度。
3. 两条 P0 原始查询不再产生普通 tool execution error，且不删除产品身份。
4. 已有中文 alias 可以召回现有资源，不依赖复制内容。
5. 超限和多主题 query 返回确定性、可执行的 focused retry queries。
6. usage 能区分 matched、zero result、complexity rejected 和 execution error。
7. true corpus gaps 使用可核验内容补充，不伪造 CVE、产品或 PoC。
8. 保持稳定资源 ID、enabled 状态、custom 资源和现有 canonical ranking。

## 非目标

- 不提高 8 个 semantic groups 上限来掩盖规划错误。
- 不把所有 query group 改为 OR。
- 不在服务端使用 LLM 改写 query。
- 不因 type 省略而把全部 nuclei vuln 混入默认技能搜索。
- 不为 usage 验证 query 创建资源。
- 不把不同产品仅因共享厂商或关键词而标为 aliases。
- 不在缺少可靠来源时编造漏洞版本、严重性、指纹或利用步骤。

## 决策一：唯一 FTS Token Contract

### 权威实现

Go `internal/tokenize` 是唯一权威 tokenizer。所有可搜索字段最终必须经过该实现：

```text
name, aliases, description, tags, category, body
  -> Go TokenizeToString
  -> resources_fts
```

Python builder 继续负责解析 AboutSecurity YAML/Markdown 和写入 raw `resources` 行，但发布产物
必须经过 Go finalizer 重建 `resources_fts`。不得在 Python 中维护第二份“等价”算法。

建议新增一个窄接口：

```go
func ReindexFTS(db *sql.DB) error
```

该接口从 `resources` raw columns 重建所有 FTS rows，并在同一 transaction 中写入：

```text
fts_contract_version=go-security-tokenizer-v2
```

build、runtime migration 和测试都调用相同接口。

### Runtime migration

启动时在打开 runtime DB 后比较 `fts_contract_version`。版本不一致时原地重建 FTS：

- 不删除或复制 `resources`；
- 保留 numeric row ID 和 stable ID identity；
- 保留 `enabled`；
- 保留 custom/team/nuclei rows；
- 在单个 transaction 内完成，失败时回滚；
- 成功后再更新 meta version。

该迁移只修复索引契约，不替代 builtin corpus 内容升级。后续 builtin 内容版本升级仍须单独
解决 runtime-owned state preservation，不得利用本次迁移清空 runtime DB。

### Build contract

`make index` 和 release image 必须执行：

```text
Python parse raw resources -> Go ReindexFTS -> contract verification
```

release contract 测试必须读取 meta 并验证 shipped DB 使用 v2 FTS contract。

## 决策二：Semantic Planner 与 FTS Compiler 分层

### Semantic groups

Planner 在 lexical tokenization 之前识别 groups。输入按 Unicode 空白和标点规范化，同时使用
versioned concept registry 做 longest-match。已知多词 alias 合并为一组，未知连续 CJK chunk
保留为一个 exact group。

示例：

```text
asp.net mvc 通用权限管理系统 systemmanage sql注入

groups:
  1. asp.net
  2. mvc
  3. 通用权限管理系统
  4. systemmanage
  5. sql_injection [sql injection, sqli, sql注入]
```

```text
learun 力软 通用权限管理系统

groups:
  1. learun [learun, 力软]
  2. 通用权限管理系统
```

同一 concept 的多个输入 aliases 只产生一个 group。

### FTS compilation

每个 group alternative 再通过权威 tokenizer 编译为 FTS 原子表达式：

```text
alias with one atom  -> "atom"
alias with many atoms -> ("atom1" AND "atom2" ...)
group aliases -> (alias1 OR alias2 ...)
query groups -> group1 AND group2 ...
```

例如：

```text
积木报表

=> ("积木" AND "木报" AND "报表")
```

索引侧对原文使用相同 tokenizer，因此表达式可稳定命中。

### Complexity limits

- raw query：最多 256 bytes；
- semantic groups：最多 8；
- 每组 aliases：最多 6；
- 编译后原子词：最多 48；
- 所有表达式通过 typed builder 生成，用户输入不得成为 FTS 运算符。

## 决策三：Planner Outcome 是公共行为

### Search response

成功结果保持向后兼容并把版本升级为 `security-concepts-v2`。新增可选字段：

```json
{
  "search_version": "security-concepts-v2",
  "status": "matched|no_match|query_too_complex",
  "total": 0,
  "items": [],
  "hint": "...",
  "retry_queries": [
    {"query":"systemmanage sql注入","type":"skill"}
  ]
}
```

`query_too_complex` 是成功解析的 tool response，不是 MCP execution error。调用方可以检查 status
并执行 retries。旧客户端忽略新字段后仍可读取 `total/items/hint`。

### Retry planning

Retry planner 必须确定性工作：

1. 保留所有已识别 product identity groups；
2. 每条 retry 最多包含一个主要漏洞/方法概念；
3. 不凭空增加 alias；
4. 不执行 retry，只返回建议；
5. 结果顺序稳定；
6. 无法可靠识别 identity 时只返回拆分提示，不猜测。

两条 P0 的预期 retries 至少包含：

```text
systemmanage sql注入
asp.net mvc 未授权
learun 力软
```

### Usage accounting

Search metrics 新增：

```text
rejected_complexity_total
queries[].rejected_complexity
```

规则：

- `matched` -> matched_total；
- `no_match` -> zero_result_total；
- `query_too_complex` -> rejected_complexity_total；
- DB/FTS/internal failure -> error_total；
- query capacity drop 规则保持不变。

## 决策四：Focused Query 与 Multi-topic Query

Focused query 保持所有 semantic groups 必须满足。服务端不通过宽泛 OR 返回部分相关内容。

以下属于 multi-topic query：

```text
php 反序列化 文件包含 日志投毒
yii 反序列化 csrf 伪造
```

它们应得到 focused retries，由调用方组合多个资源。只有当 AboutSecurity 中确实存在经过维护的
组合攻击链 Skill 时，原 query 才应直接命中该 Skill。

## 决策五：默认 Vuln Policy 保持不变

type 省略时继续排除 vuln，避免约 3,000 条 nuclei 记录淹没方法论资源。

no-type zero result 的 hint 必须明确说明：

```text
Vulnerabilities are excluded by default; retry with type="vuln" when the query is a CVE,
product vulnerability, endpoint, or PoC lookup.
```

服务端不在后台执行第二次 vuln search。以下验收因此调整为 retry 行为：

- `queryfieldbysql` 无 type -> `no_match` + `type=vuln` hint；
- `积木报表` 无 type -> `no_match` + `type=vuln` hint；
- `积木报表`, type=vuln -> existing JMReport CVE match。

## PoJun 调用方约束

PoJun Review prompt 必须补充：

- query 使用空格分隔的核心产品/技术关键词，不复制完整 Intent 描述；
- 单次 query 最多 4 个 semantic groups；
- 一个 query 聚焦一个产品或技术；
- 攻击链允许多次 `search_security`；
- 收到 `query_too_complex` 时只使用返回的 deterministic retries；
- 收到 vuln hint 时显式指定 `type=vuln`。

usage v1 不关联 client family 与具体 query，因此本设计不声称历史 P0 一定来自 PoJun；调用方修复
是防御性约束。

## AboutSecurity 内容模型

### Alias 规则

- aliases 表示同一产品、组件或安全概念的等价身份；
- 厂商相同、技术栈相同或路径相似不构成 alias；
- aliases 进入 FTS identity 字段并参与 canonical ranking；
- v2 首阶段可继续使用受控 tags 表达 aliases，后续再设计独立 schema；
- 中文 alias 必须通过统一 tokenizer 的端到端 corpus test。

### 新内容规则

新增 Vuln 必须包含：

- stable ID；
- title、product、vendor、version_affected、severity、tags、fingerprint；
- 可核验描述、前置条件、验证方法和来源；
- PoC 仅在可靠来源支持时加入。

新增 Skill 必须包含：

- canonical name；
- 可触发的 description；
- category、tags/product aliases；
- 可执行方法、决策点、验证方法和边界；
- 与现有通用 Skill 的关系，避免复制大段内容。

## 生产查询验收矩阵

| Query | Type | 分类 | v2 预期 |
| --- | --- | --- | --- |
| `.net 后台 jqgrid getgridjson 未授权 sql注入` | skill | true content gap | 命中经核验的 ASP.NET/JQGrid 方法论 |
| `asp.net mvc 控制器枚举 未授权` | all | true content gap | 命中 ASP.NET MVC endpoint/auth assessment Skill |
| `aspnet mvc 后台 systemmanage 注入` | skill | planner + content | 不超限；命中 SystemManage/Learun 方法论 |
| `cve-2024-44893 jmreport` | vuln | true content gap | 命中精确 CVE stable ID |
| `jeecg-boot jmreport 未授权` | skill | true content gap | 命中 JEECG/JMReport assessment Skill |
| `nfine 快速开发平台 getgridjson` | vuln | true content gap | 命中经核验 NFine vuln；无可靠记录时明确 unsupported |
| `nros 久其 框架` | all | true content gap | 命中 NROS product assessment resource |
| `久其 nros gsi 未授权` | all | true content gap | 命中经核验 NROS/GSI resource |
| `php 反序列化 文件包含 日志投毒` | all | multi-topic | 返回 focused retries，或命中真实组合攻击链 Skill |
| `phpcms` | all | true content gap | 命中 PHPCMS canonical resource |
| `phpcms 9.6.0` | vuln | true content gap | 命中明确覆盖 9.6.0 的经核验 vuln |
| `queryfieldbysql` | all | filter | no_match + retry type=vuln |
| `trs wcm 拓尔思` | vuln | partial/true gap | 不把 TRS 媒资漏洞误标为 WCM；命中经核验 WCM vuln |
| `yii 反序列化 csrf 伪造` | skill | multi-topic/content | focused retries，或命中真实 Yii assessment Skill |
| `网神 终端安全 反序列化` | skill | true content gap | 不把金山 V8 误标为网神；命中经核验 resource |
| `chinese china` | dict | alias gap | 命中中文姓名/拼音 dict，不复制字典 |
| `密码字典 弱口令 常用密码` | dict | tokenizer recall | Top result 为 builtin auth/password canonical dict |
| `政府 默认口令` | dict | true content gap | 仅在取得政务设备凭据语料后命中；否则明确 unsupported |
| `积木报表` | all | tokenizer + filter | no_match + retry type=vuln |
| `积木报表` | vuln | tokenizer recall | 命中 `CVE-2023-1454`，并可返回其他 JMReport vulns |

额外 P0：

| Query | Type | v2 预期 |
| --- | --- | --- |
| `asp.net mvc 通用权限管理系统 systemmanage sql注入` | skill | 不产生 tool error；保留 SystemManage identity；返回 match 或 focused retries |
| `learun 力软 通用权限管理系统` | all | 不产生 tool error；Learun/力软合并为同一 identity group |
| `systemmanage sql注入` | skill | 命中相关方法论 |
| `learun 力软` | all | 命中相关方法论 |

## TDD 实施顺序

每个 cycle 必须先通过公共接口建立一个失败行为，再写最小实现。禁止先批量写完测试。

### Slice 1：FTS contract tracer bullet

1. RED：用公共 `search.Search` 证明含 `积木报表` 的 raw resource 无法被相同 query 召回。
2. GREEN：增加 `ReindexFTS`，同一个 Go tokenizer 负责 resource 和 query。
3. RED/GREEN：runtime migration 保留 enabled/custom/stable identity。
4. RED/GREEN：build finalizer 和 release meta contract。

### Slice 2：Semantic groups

1. RED：P0 SystemManage 原 query 可规划且不超过 8 semantic groups。
2. GREEN：semantic parser 与 FTS compiler 分层。
3. RED/GREEN：Learun/力软 aliases 合并为一组。
4. RED/GREEN：原子词 48 上限与 FTS escaping。

### Slice 3：Complexity outcome

1. RED：真正超限 query 返回 `query_too_complex` response，而不是 tool error。
2. GREEN：typed planner outcome 和 deterministic retries。
3. RED/GREEN：usage 计入 rejected，不计入 zero/error。

### Slice 4：Filter hints 与调用方

1. RED/GREEN：no-type no-match 明确提示 type=vuln。
2. RED/GREEN：`queryfieldbysql` 保持默认排除，不后台 fallback。
3. RED/GREEN：PoJun Review prompt 约束 focused query 和 complexity response。

### Slice 5：Corpus gaps

按查询逐个循环：

1. 先确认 pinned AboutSecurity revision 和 nuclei 支持目录没有等价资源；
2. RED：fresh built corpus query 失败；
3. GREEN：补最小可靠 Skill/Vuln/metadata；
4. 验证 expected stable ID 和 full detail；
5. 更新 AboutSecurity revision pin 后再处理下一项。

不得把所有 19 条测试一次性写完后再集中补内容。

## 回归与性能

每个 slice 后运行相关 package tests；最终必须通过：

```text
go test ./...
go test -race ./...
go vet ./...
python3 -m unittest build.test_build_index -v
make test-release-image IMAGE=<candidate>
```

Golden 必须保持：

- `JWT algorithm confusion` -> `jwt-attack-methodology` Top 1；
- `SQL injection` -> `sql-injection-methodology` Top 1；
- `password` -> canonical password dictionaries；
- `jmreport`, type=vuln -> existing JMReport CVEs；
- disabled/source/category/severity/product filters；
- stable ID ordering；
- representative search p95 <= 20ms，并记录 v1/v2 对照。

## 发布顺序

1. 在 context1337 合入 v2 search、migration 和完整回归。
2. 在 AboutSecurity 合入逐条核验的内容补充。
3. 更新 release workflow 的 `ABOUTSECURITY_COMMIT` pin。
4. 构建固定 AboutSecurity/nuclei revisions 的 candidate image。
5. canary 复放全部查询，检查 status、Top IDs、usage buckets 和 session 行为。
6. 先发布 context1337，再发布 PoJun focused-query prompt。

## 回滚

- binary 可回滚到 v0.7.6；raw `resources` 数据不因 FTS migration 改变；
- v2 FTS 可由 raw columns 确定性重建；
- PoJun 必须把 `security-concepts-v2` 与 v1 resolution 分开，不复用旧 binding；
- AboutSecurity content commit 独立，可单独回滚 pin；
- 回滚不应删除 custom resources 或 enabled overrides。
