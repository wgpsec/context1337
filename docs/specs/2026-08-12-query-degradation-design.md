# Context1337 查询降级与中文拼音转写设计规范

## 状态

- 日期：2026-08-12
- 状态：已按 TDD 本地实施，待 commit/release
- 影响仓库：`context1337`
- 关联规范：
  - `docs/specs/2026-08-11-security-concepts-v2-design.md`
  - `docs/specs/2026-08-12-security-concepts-v2-closure-design.md`
- 生产案例：360 天擎资源 `absec://nuclei/vuln/CNVD-2021-32799`

## 摘要

生产环境已经包含 360 天擎对应的 nuclei 资源，但中文查询仍可能返回零结果：

- 上游模板有 `360`、`Tianqing`、`xintianqing`，没有中文“天擎”；
- 查询侧没有通用的中文产品名转写能力；
- `getsimilarlist 360 tianqing sqli` 等过度限定查询继续使用组间 `AND`，任一不存在的限定词都会使整条查询零结果；
- 当前 `no_match` 没有说明系统已经尝试过什么，也不能指导 LLM 下一步如何改写。

逐产品维护 `天擎 -> Tianqing` 一类静态 alias 会随着产品数量线性增加维护成本，不能作为通用方案。
本规范改为确定性的三阶段流程：

1. 始终先执行原始完整 AND 查询；
2. 只有原始查询完全零结果时，将 planner 未识别的中文 `context` 组转成无声调拼音，最多执行一次完整拼音查询；
3. 拼音仍无结果时返回 `no_match`，结构化提示调用方/LLM 将中文关键词翻译为英文，或减少非必要关键词后重试。

Context1337 不调用 LLM、不自动删除关键词、不执行宽泛 OR、不维护产品级 alias，也不修改 PoJun 的查询或调度逻辑。

## 已确认决策

| 决策 | 结论 | 原因 |
| --- | --- | --- |
| 降级触发 | 仅原始完整 AND 查询在相同过滤条件下候选数为 0 | 精确命中路径零行为变化 |
| 自动降级 | 最多执行一次中文 context 拼音查询 | 能直接解决中英文产品名转写问题，成本可控 |
| 拼音格式 | 小写、无声调、连续拼写 | 与 `tianqing` 等英文索引形态一致 |
| 多音字 | 使用依赖库的确定性默认读音，不生成组合 | 避免候选爆炸和不稳定结果 |
| 后续处理 | 拼音仍无结果时只返回英译/减词建议 | 语义翻译交给 LLM，Context1337 保持确定性 |
| 产品 alias | 不维护产品、厂商、endpoint 静态 alias | 避免长期维护成本 |
| 安全概念 registry | 继续保留 | `SQL注入 -> sqli` 属于语义等价，拼音无法替代 |
| PoJun 改动 | 本轮不需要 | 搜索降级属于 Context1337；PoJun 只消费响应 |

## 现有行为

```text
raw query
  -> PlanQuery（semantic groups + FTS expression）
  -> 单次 FTS 查询（组间 AND）
  -> relevance trim / type diversify
  -> matched 或 no_match
```

当前 `retry_queries` 只覆盖：

- `query_too_complex`；
- 已识别多个 topic 的 multi-topic `no_match`。

它不能处理未知中文产品或组件名称，也没有告诉 LLM exact query 失败后应该先英译还是减词。

## 术语

- **Query group**：`PlanQuery` 生成的一个必选语义组；组内 aliases 为 OR，组间为 AND。
- **identity**：已识别的框架或技术身份，如 `php`、`learun`。
- **topic**：漏洞类型、攻击方法或调查主题，如 `sqli`、`ssrf`、`反序列化`。
- **context**：planner 未归入 identity/topic 的原始限定词，包括产品、厂商、endpoint 和组件名。
- **拼音转写**：只转换字形，不推断语义；例如 `天擎 -> tianqing`。
- **英文翻译**：把中文语义翻译为英文；只能由调用方/LLM 执行，不属于拼音转写。
- **完全零结果**：原始完整 expression 在相同 filters 下、裁剪前和分页前的候选总数为 0。

## 目标

1. `query="天擎 360 sqli", type="vuln"` 能通过一次确定性拼音降级命中已有 `Tianqing` 资源。
2. 拼音命中保持原始完整 AND 语义，不删除 endpoint、漏洞类型或其他关键词。
3. 拼音仍无结果时，给 LLM 返回可执行且有顺序的英译/减词建议。
4. 精确命中、默认 vuln 排除、filters、canonical ranking、stable ID 和 FTS escaping 保持不变。
5. 响应明确说明原始 query、有效 query、转写映射和已尝试策略。
6. 每次搜索最多增加一次 FTS 查询，不产生查询风暴。
7. 真实内容缺口不被伪装成命中。

## 非目标

- 不把组间 `AND` 改成 `OR`；
- 不自动删除任何原始 query group；
- 不使用 LLM、机器翻译、embedding、编辑距离或模糊匹配；
- 不自动执行英译或减词后的查询；
- 不生成多个多音字拼音候选；
- 不改变默认不搜索 vuln 的策略；
- 不在 PoJun Dispatcher、Resolver、Worker 或 OODA 中复制降级逻辑；
- 不为了命中而补充未经验证的 endpoint、漏洞、版本或利用内容；
- 不新增 SQLite 表、永久 override 或独立 runtime 数据库。

## 设计一：Security Concept 与 Product Context 分离

现有 `SecurityConcept` registry 继续维护经过确认的安全语义等价词：

```go
{
    ID: "sql_injection",
    Aliases: []string{"sql injection", "sqli", "sql注入"},
    Role: ConceptRoleTopic,
}
```

这是必要的语义映射，因为 `sql注入` 的拼音 `sqlzhuru` 不等于 `sqli`。

registry 不再承担产品目录职责：

- 不为 `天擎/Tianqing/xintianqing` 新增产品 concept；
- 不为厂商、产品、endpoint 或组件名逐条维护 aliases；
- 已存在且服务于安全语义/ranking 的 concepts 不在本轮删除；
- 后续新增 alias 必须证明是安全概念等价词，而不是特定产品翻译。

## 设计二：拼音转写器

### 转写范围

一个 group 只有同时满足以下条件才参与转写：

1. `Role == context`；
2. `ConceptID == ""`，即未被安全 concept registry 识别；
3. group 包含至少两个连续 Han 字符；
4. group 不包含 URL、路径、版本号、CVE/CNVD/GHSA 等受保护结构；
5. 单次 query 可转写的 group 不超过 3 个。

混合组采用保守策略：仅在整个 group 都由 Han 字符组成时转写。`xx天擎/api`、`v2天擎` 等混合值保持原样，由 LLM 后续处理。

### 输出规则

- 输出小写；
- 去除声调；
- 汉字音节连续拼接，不加空格或连字符；
- 保持原 group 顺序；
- 不展开多音字组合；
- 无法转写的字符保持该 group 原样；
- 转写后与原文相同则不产生候选。

示例：

```text
query="天擎 360 sqli", type="vuln"
  -> tianqing 360 sqli

积木报表 sql注入
  -> jimubaobiao (sql injection OR sqli OR sql注入)
```

第二个例子中只有未知 context `积木报表` 转写；已识别 topic `sql注入` 继续使用现有安全概念 aliases。

### 依赖要求

- 选择维护中的纯 Go 汉字拼音库；
- 固定依赖版本并纳入 `go.sum`；
- 不调用外部 API，不下载运行时字典；
- 依赖必须支持当前 Go 版本、race test 和静态构建；
- 用项目级 wrapper 隔离第三方 API，搜索代码只依赖窄接口：

```go
type Transliterator interface {
    Pinyin(text string) (string, bool)
}
```

默认实现失败时返回 `false`，搜索回退为原始 `no_match`，不得使 MCP tool 执行失败。

## 设计三：触发条件与阶段流程

### “完全没有结果”的精确定义

只有原始完整 AND FTS expression 在相同的
`type/category/source/severity/product/visibility` 条件下返回候选总数 `0`，才允许拼音降级。

以下情况不得触发：

- FTS 有候选，但 relevance cutoff 将当前页裁剪为空；
- `offset` 超出结果集导致当前页为空；
- 客户端渲染、网络或响应解析导致调用方未看到结果；
- 搜索执行失败或 query complexity 被拒绝；
- `offset > 0` 的分页请求。

判断必须使用裁剪前、分页前的 exact candidate total，不能依据最终 `items` 长度。

### 阶段流程

```text
原始 PlanQuery
  -> 完整 AND FTS 查询
  -> 有候选：返回 exact
  -> 完全零候选：BuildPinyinFallback(plan)
      -> 无可转写中文 context：返回 no_match + LLM guidance
      -> 有候选：执行一次完整拼音 AND 查询
          -> 命中：返回 transliterated matched
          -> 零结果：返回 no_match + LLM guidance
```

拼音候选必须保留：

- 所有 identity/topic groups；
- 所有非中文 context groups；
- `type/category/source/severity/product/visibility` filters；
- 原始 group 顺序和组间 AND 关系。

降级不放宽 filters。若调用方省略 `type="vuln"`，即使拼音可以正确转写，nuclei 资源仍按默认
策略被排除，最终响应继续提示显式使用 `type="vuln"`。

例如：

```text
getsimilarlist 360 天擎 sqli
  -> getsimilarlist AND 360 AND tianqing AND sql_injection_aliases
```

由于 `getsimilarlist` 仍不存在，该 query 仍应 `no_match`。Context1337 不自动删除它，只提示 LLM 减少限定词。

## 设计四：响应契约

### 拼音命中

保持 `status` 枚举不变，新增可选字段：

```json
{
  "search_version": "security-concepts-v3",
  "status": "matched",
  "total": 1,
  "items": [
    {"id": "absec://nuclei/vuln/CNVD-2021-32799", "name": "..."}
  ],
  "resolution": {
    "mode": "transliterated",
    "original_query": "天擎 360 sqli",
    "effective_query": "tianqing 360 sqli",
    "transliterations": [
      {"from": "天擎", "to": "tianqing"}
    ],
    "reason": "chinese_context_transliteration"
  },
  "attempted_strategies": ["exact", "pinyin"],
  "hint": "Exact query returned no results. Showing results after deterministic Chinese-to-pinyin transliteration."
}
```

规则：

- exact 命中不返回 `resolution` 和 `attempted_strategies`，保持响应紧凑；
- 拼音命中必须返回 `mode=transliterated`、原始 query、有效 query 和完整映射；
- `transliterations[].from` 必须来自原始 query；
- `transliterations[].to` 必须是转写器的确定性输出；
- 不返回内部 SQL、rowid、posting 数量或数据库路径；
- `retry_queries` 的既有 multi-topic/complexity 语义保持不变。

### 拼音仍无结果

```json
{
  "search_version": "security-concepts-v3",
  "status": "no_match",
  "total": 0,
  "items": [],
  "attempted_strategies": ["exact", "pinyin"],
  "retry_guidance": [
    {
      "action": "translate_to_english",
      "reason": "chinese_context_not_found"
    },
    {
      "action": "reduce_keywords",
      "reason": "focused_query_returned_no_results"
    }
  ],
  "hint": "Exact and pinyin searches returned no results. Translate Chinese product or component terms to English, or remove non-essential keywords and retry."
}
```

规则：

- `retry_guidance` 只描述动作，不替 LLM生成未经验证的英文词；
- 有中文 context 且执行过拼音时返回 `exact,pinyin`；
- 没有可转写中文 context 时只返回 `attempted_strategies=["exact"]`；
- `translate_to_english` 只在原 query 含未识别中文 context 时返回；纯 ASCII no-match 只建议 `reduce_keywords`；
- `reduce_keywords` 不指定删除哪个词，除非现有 focused retry planner 已有确定性的 topic 拆分；
- Context1337 不自动执行 guidance。

## 设计五：错误、过滤与分页

- 原始查询 SQL/FTS 错误：保持现有 execution error，不尝试拼音；
- 转写器或拼音候选查询失败：降级失败关闭，返回原始 `no_match`，不向客户端暴露内部错误；
- type 省略排除 vuln：拼音查询不自动切换 `type=vuln`；hint 继续提示调用方显式指定；
- `product` filter 与 query identity 同时存在时全部保留；
- `offset > 0` 不执行拼音降级，避免第一页和后续页结果集不稳定；
- `limit`、relevance cutoff、type diversification 对 exact 和 transliterated 结果一致；
- `query_too_complex` 不进入拼音阶段，继续返回现有 focused retries。

## 设计六：Usage 与可观测性

Context1337 usage 增加可选字段：

```json
{
  "search": {
    "transliterated_total": 3,
    "queries": [{
      "query": "天擎 360 sqli",
      "transliterated": 1,
      "transliterations": [
        {"from": "天擎", "to": "tianqing"}
      ]
    }]
  }
}
```

计数规则：

- exact matched 只计 `matched_total`；
- transliterated matched 同时计 `matched_total` 和 `transliterated_total`，不计 zero result；
- exact 与 pinyin 都无结果时只计一次 `zero_result_total`；
- complexity rejection 仍只计 `rejected_complexity_total`；
- 拼音内部失败不额外增加原始 query 的 `error_total`；服务端日志记录限频诊断；
- 本轮不要求 PoJun 页面消费新字段；旧 PoJun 忽略未知字段仍兼容；
- benchmark/trace 记录 query digest、resolution mode、effective query 和转写映射。

## 设计七：实现边界

### Context1337

预计修改范围：

- 新增 `internal/transliterate/`：第三方拼音库 wrapper 和纯函数测试；
- `internal/search/query_plan.go`：识别可转写中文 context，构造单一拼音候选；
- `internal/search/index.go`：复用相同 filters 执行一次候选查询；
- `internal/mcp/unified.go`：在原始完全零结果后调用拼音降级，组装 resolution/guidance；
- `internal/usage/collector.go`：记录 transliterated 计数与映射；
- 对应 search、MCP、usage 测试。

### 不修改

- PoJun Resolver、Dispatcher、Worker、OODA 或 MCP 调度路径；
- SQLite schema、stable ID、resource source、enabled 状态；
- nuclei 文件内容和 AboutSecurity corpus；
- 现有安全 concept aliases 和默认 vuln policy。

## TDD 实施顺序

### 第 1 步：红灯，锁定生产复现

1. fixture 加入 `CNVD-2021-32799` 最小资源，包含 `360,tianqing,xintianqing,sqli`，不含“天擎”；
2. `query="天擎 360 sqli", type="vuln"` 当前为 `no_match`，新增测试期望通过拼音命中同一 stable ID；
3. `query="getsimilarlist 360 天擎 sqli", type="vuln"` 期望 exact/pinyin 均无结果，并返回英译/减词 guidance；
4. `sql注入` 必须继续走安全 concept aliases，不转成 `sqlzhuru`；
5. CVE、版本号、URL、路径、单汉字、混合 group 不转写；
6. 多个中文 context 只生成一个完整拼音候选，不展开多音字组合；
7. exact query 有候选时断言转写器未被调用。

### 第 2 步：最小实现

1. 引入并封装固定版本拼音依赖；
2. 实现 `BuildPinyinFallback(plan)` 纯函数；
3. 在 `Service.Search` 的 `exactTotal==0 && offset==0` 分支执行最多一次候选；
4. 添加 `resolution`、`attempted_strategies` 和 `retry_guidance`；
5. 添加 usage 字段，保持旧 snapshot JSON 兼容；
6. 更新 MCP tool 描述，提示调用方按 guidance 重试，禁止重复 exact/pinyin 查询。

### 第 3 步：回归与门禁

- `go test ./...`；
- `go test -race ./...`；
- `go vet ./...`；
- 生产候选 corpus 查询矩阵：
  - `360`、`tianqing`、`xintianqing` 继续 exact 命中；
  - `query="天擎 360 sqli", type="vuln"` 通过 pinyin 命中同一 stable ID；
  - `query="getsimilarlist 360 天擎 sqli", type="vuln"` 仍为 no-match，且 guidance 完整；
  - 相同天擎 query 省略 type 时继续 no-match，并明确提示 `type="vuln"`；
  - `getsimilarlist` 单词查询不产生宽泛结果；
  - `CVE-2021-32799` 只有 `type=vuln` 时命中；
  - 未验证 endpoint 不因拼音降级产生伪命中；
- 重复请求输出 JSON 除 usage 时间字段外完全一致；
- 断言 exact 命中 1 次查询、可降级 no-match 最多 2 次查询。

## 性能与风险控制

- exact 命中路径增加零额外查询和零拼音转换；
- exact no-match 最多增加一次内存转写和一次 FTS 查询；
- 每次最多转写 3 个中文 context group；
- 仅 `offset=0` 触发，避免分页结果漂移；
- 不缓存跨请求的转写决定，避免索引更新后陈旧结论；
- 转写结果必须结构化返回，调用方可以审计；
- 回滚只需关闭拼音降级调用，旧客户端仍可消费原响应字段；
- 拼音同形/多音字可能产生误召回，因此不允许降级修改 AND 结构，最终结果仍需满足全部转写后 groups。

## 验收标准

1. exact 命中路径结果和查询次数不变；
2. 360 天擎案例通过拼音转写命中，stable ID 不变；
3. 未索引 endpoint 不被自动删除；
4. 已识别安全概念不被错误拼音化；
5. protected identifiers、filters、默认 vuln policy 不被改变；
6. 拼音命中和最终 no-match 都可解释、可审计、可重复；
7. 无产品 alias、无 LLM、无 OR fallback、无 PoJun 业务逻辑改动；
8. 测试和性能门禁全部通过后，才允许更新 release image。

## 已确认范围

- 服务端仅在原始查询完全零结果时自动执行一次拼音候选；
- 拼音仍无结果时，由响应提示 LLM 英译或减少关键词；
- Context1337 本身不执行英文翻译和删词查询；
- 不采用逐产品 registry alias 方案。

## 实施结果

- 搜索契约升级为 `security-concepts-v3`；
- 新增固定版本纯 Go 拼音依赖与 `internal/transliterate` wrapper；
- 原始完整查询完全零结果且 `offset=0` 时，最多执行一次中文 context 拼音查询；
- exact 命中、安全 concept、默认 vuln 过滤和后续分页均不进入拼音降级；
- 拼音命中返回 `resolution` 和 `attempted_strategies`；
- 拼音仍无结果返回英译/减词 `retry_guidance`，且保留原有 type/filter hint；
- usage 增加 `transliterated_total`、单 query 次数和确定性转写映射；
- 未实现产品 alias、自动删词、OR fallback、LLM 翻译或 PoJun 改动。

本地验证：

- `go test ./... -count=1`；
- `go test -race ./...`；
- `go vet ./...`；
- `git diff --check`。
