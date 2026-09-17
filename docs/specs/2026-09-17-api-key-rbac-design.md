# Context1337 API Key RBAC 设计

## 状态

- 日期：2026-09-17
- 状态：Implemented
- 目标仓库：`context1337`
- 非目标仓库：PoJun 控制面本期不改；现有 `ABOUTSECURITY_API_KEY` 升级后仍是管理员密钥

## 摘要

当前只有一个 `ABOUTSECURITY_API_KEY`。通过认证的调用者能读全部 `source`（含私有 `team`），也能走 REST 写接口（`custom` CRUD、任意资源 `toggle`、`GET /api/usage`）。MCP 与 REST 共用这把钥匙。

本期给密钥补两轴权限：**可见 source** 和 **读/写**。不引入用户账号、OAuth、按资源 ACL，也不做 team 的 REST 写入。

## 已锁定决策

无需再确认：

- `nuclei` 跟 `builtin` 同属公开语料。授权 `builtin` 即能读 `nuclei`。调用方仍可按 `source=nuclei` 过滤，但不能单独授权 nuclei、禁止 builtin。
- `team` 是私有覆盖层，必须显式授权。未授权时搜索/列表/详情/MCP/读文件都不可见。
- `custom` 是运行时 REST 覆盖层，不是 git 语料。读、写都要单独授权。
- 语料写入路径不变：`builtin` 走公开仓 + 镜像；`team` 走 zip 挂载；REST 只能写 `custom`。本期不增加 team 的 POST/PUT/DELETE。
- `ABOUTSECURITY_API_KEY` 保持向后兼容：有值且没有更细配置时，行为与现在相同（全 source、可写、可看 usage）。
- 密钥为空时仍是开发模式：不鉴权，可见全部 source。`GET /api/usage` 在无密钥时继续 404。
- MCP 工具本身没有写操作。写权限只约束 REST。MCP 仍受该密钥的 source 可见性约束。
- 未授权的 `source=` 显式过滤返回 403，不返回空列表。无 `source=` 的搜索则静默只搜已授权 source，避免把权限问题记成零结果。
- 按 id / stable id 读取未授权 source 的资源返回 404，不泄露存在性。
- `/health` 继续免鉴权，且不暴露 source 计数。

## 当前问题

生产同一把密钥同时给：

- 公网 `https://1337.ncsec.cn` / MCP 客户端
- 内部 PoJun agent
- 运维 REST（建 custom、toggle、看 usage）

因此任意持有该密钥的客户端都能搜到 `source=team` 的私有漏洞，也能 `PUT /api/resources/{id}/toggle` 关掉 builtin/team 行。`custom` CRUD 虽不能改 builtin 文件，但 toggle 已经是跨 source 的写。

## 授权模型

每个密钥是一个 principal：

```text
id        稳定名字，只用于日志/排障，不进 MCP 响应
key       Bearer 明文；只存在环境或密钥文件
sources   可见 source 集合
access    ["read"] and/or ["write"]
```

### sources

允许值：`builtin`、`team`、`custom`。

展开规则：

| 授权 | 实际可读 |
| --- | --- |
| `builtin` | `builtin` + `nuclei` |
| `team` | `team` |
| `custom` | `custom` |

`sources` 为空非法。启动时拒绝加载。

### access

读和写是独立权限，可以只读、只写，或读写都有。

| access | REST 读 | MCP 读 | custom CRUD | toggle / batch-toggle | GET /api/usage |
| --- | --- | --- | --- | --- | --- |
| `["read"]` | 已授权 source | 已授权 source | 403 | 403 | 403 |
| `["write"]` | 403 | 403 | 需要 `custom` ∈ sources，否则 403 | 只允许作用于已授权 source | 允许 |
| `["read","write"]` | 已授权 source | 已授权 source | 需要 `custom` ∈ sources，否则 403 | 只允许作用于已授权 source | 允许 |

`write` 仍然不能修改 `builtin` / `nuclei` / `team` 的内容字段。PUT/DELETE 非 custom 继续 403。toggle 只改 `enabled`，且 WHERE source 必须落在该密钥的授权集合内；越权 id 视为 404。

文件里旧的字符串 `"access":"write"` 仍表示读写都有，避免已有密钥丢查询能力。管理台新写入一律用数组。

管理员不是第三种 access。它就是 `sources=[builtin,team,custom]` + `access=["read","write"]`，由 `ABOUTSECURITY_API_KEY` 自动生成。

### 推荐发放

| 用途 | sources | access |
| --- | --- | --- |
| 公网 / 外部 MCP | `[builtin]` | `["read"]` |
| 内部 PoJun / 可消费私有库的 agent | `[builtin, team]` | `["read"]` |
| 运维 REST、custom 补丁、停用条目、看 usage | `[builtin, team, custom]` | `["read","write"]` |

## 密钥加载

两处来源，启动时合并，冲突即失败：

1. `ABOUTSECURITY_API_KEY`：若非空，生成 id=`bootstrap`、全 sources、`access=["read","write"]`。
2. `ABOUTSECURITY_API_KEYS_FILE`：额外密钥 JSON。未设置时使用 `{dataDir}/runtime/api-keys.json`。文件不存在视为没有额外密钥；管理台会创建并写回该文件。必须挂到 runtime volume，不要放进 team zip，也不要写进镜像。

文件格式：

```json
[
  {
    "id": "public-mcp",
    "key": "replace-me",
    "sources": ["builtin"],
    "access": ["read"]
  },
  {
    "id": "pojun-agent",
    "key": "replace-me",
    "sources": ["builtin", "team"],
    "access": ["read"]
  },
  {
    "id": "ops",
    "key": "replace-me",
    "sources": ["builtin", "team", "custom"],
    "access": ["read", "write"]
  }
]
```

校验：

- `id`、`key` 非空；`id` 与 `key` 都不得重复（含 bootstrap）。
- `key` 不得等于其他 principal 的 `id`。
- `sources` 只允许上述三值；未知值启动失败。
- `access` 可以是字符串 `read`/`write`（旧格式，`write` 含读），或数组 `["read"]` / `["write"]` / `["read","write"]`。
- 有 `write` 但 `sources` 不含 `custom` 时，custom CRUD 恒 403；toggle / usage 仍可用。这是合法组合（例如只准停用、不准造 custom）。

密钥只在内存比较，不入库、不写 usage 快照。日志只打 `id`，禁止打 key。

鉴权方式不变：REST 用 `Authorization: Bearer`；MCP 同时接受 Bearer 与 `?api_key=`。匹配到任一 principal 即进入该请求的授权上下文。

## 执行点

鉴权中间件从“等于那一个字符串”改为“解析 principal，写入 request context”。后续 handler / MCP service 只读 context，不再自己比对密钥。

必须强制 source 约束的路径：

- REST：`GET /api/resources`、`GET /api/stats`、`GET /api/health` 的计数、`POST/PUT/DELETE /api/resources`、`PUT .../toggle`、`PUT .../batch-toggle`
- MCP：`search_*`、`list_*`、`get_*`、`get_security_detail`、`read_security_file` / `GetFile`
- 搜索层：`SearchQuery` 增加允许的 source 列表。调用方传了未授权 `source` 时，在 API/MCP 边界返回 403，不要落到“零结果”。

`GET /api/stats` 与认证后的 `/api/health` 只汇总已授权 source。公网只读密钥不能靠 stats 发现 team 资源量。

`GET /api/usage` 只对有 `write` 的密钥开放。只读密钥看 usage 会把别人的 team 查询词泄露出去。

## 兼容与发布

- 只配 `ABOUTSECURITY_API_KEY`、密钥文件不存在：生产行为不变，现有 PoJun / 运维脚本不用改。`/admin` 仍关闭，直到另设独立的 `ABOUTSECURITY_ADMIN_KEY`。
- 配了密钥文件或经管理台创建密钥之后，公网应改用 `builtin` 只读密钥；内部 agent 用带 `team` 的只读密钥；当前 bootstrap 密钥收回公网。
- 本期不改 PoJun 配置 schema。PoJun 继续只持有一把密钥；发哪一把是部署选择。
- 镜像版本随 Context1337 发版，不热补。

## 非目标

- 不给 team 做 REST 写入或 zip 上传接口。
- 不按资源、产品、用户做 ACL。
- REST 不做密钥轮转；密钥增删改/轮换走 `/admin` 管理台。不做审计日志落库、IP 限制、配额。
- 不把 principal id 写进 MCP tool 输出或 usage query 维度（避免把内部角色名泄漏给模型）。
- 不改变 tokenizer、排序、语料所有权。

## 验收

- bootstrap 单密钥：现有 REST/MCP 契约测试继续绿。
- `builtin` 只读密钥：能搜到 builtin/nuclei；`source=team` 为 403；无 filter 的搜索结果不含 team；GetFile team 路径 404；POST custom / toggle / usage 为 403。
- `builtin+team` 只读密钥：能搜到 team 私有 ID；POST custom 403。
- write 且含 custom：可建/改/删 custom，不能改 builtin 内容。
- write toggle：不能 toggle 未授权 source。
- 密钥文件非法（重复 key、未知 source）时进程拒绝启动。
- 日志出现 principal id，不出现密钥明文。

## 实现顺序

1. principal 解析 + request context，bootstrap 兼容。
2. 搜索/列表/MCP/GetFile 的 source allowlist。
3. REST 写接口与 usage 的 access 检查。
4. 密钥文件加载与启动校验。
5. 契约测试覆盖上面四类密钥。
