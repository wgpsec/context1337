# Context1337 Admin Console

## 状态

- 日期：2026-09-17
- 状态：Implemented
- 版本：0.7.13
- 目标仓库：`context1337`

## 摘要

`/admin` 用来可视化管理 MCP/REST API key：创建、改 source/access、轮换、删除。登录只用独立超管密钥 `ABOUTSECURITY_ADMIN_KEY`。资源总览/启停和用量是附带能力，不是管理台主功能。

## 已锁定

- 超管密钥不进入密钥文件，也不能当 Bearer 调 `/mcp` 或 `/api/*`。
- 与任一 MCP/REST 密钥相同则启动失败；管理台创建/轮换也禁止撞这把钥匙。
- 未设置超管密钥时 `/admin` 关闭（404）。只配 `ABOUTSECURITY_API_KEY` 时生产 MCP/REST 行为不变。
- 登录发 HttpOnly cookie（12h，Path=`/admin`）。
- 明文密钥只在创建或轮换响应里出现一次，列表不返回明文。
- `ABOUTSECURITY_API_KEY` 对应的 `bootstrap` 密钥归环境变量，管理台只读，不能改、轮换、删除。
- 管理台创建的密钥立刻对 MCP/REST 生效，并写回密钥文件。
- 密钥文件：显式 `ABOUTSECURITY_API_KEYS_FILE`，否则 `{dataDir}/runtime/api-keys.json`。该路径需要持久化卷。emptyDir 会在重启后丢掉管理台密钥。

## 密钥模型

与 RBAC 相同：`id` + `access=["read"]` / `["write"]` / `["read","write"]` + `sources=[builtin,team,custom]`。读和写独立勾选，不是二选一。`builtin` 含 `nuclei`。旧文件 `"access":"write"` 仍表示读写都有。

## 升级

1. 先带原 `ABOUTSECURITY_API_KEY` 发版，公网 MCP 继续用 bootstrap。
2. 另设独立 `ABOUTSECURITY_ADMIN_KEY` 后打开 `https://<host>/admin`。
3. 在管理台创建公网只读、内部 agent、运维读写密钥，再把 bootstrap 从公网收回。
4. 升版时新 runtime volume 要拷贝旧卷的 `api-keys.json`，不要只拷 `runtime.db`。

## 非目标

- 不把超管密钥做成第三把 MCP key。
- 不在管理台展示已有密钥明文。
- 不给 team 做 zip 上传。
