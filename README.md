# Team Access Platform

基于 HTTP 的组织成员与权限管理服务。FastAPI + SQLite（WAL、文件持久化、原子事务）。

## 功能概览

- **账号 / 会话**：唯一用户名 + 密码注册、登录、退出；用户名重复返回 `409`；
  密码使用 PBKDF2-HMAC-SHA256 加盐哈希存储，永不明文落盘或出现在任何响应中；
  退出立即吊销当前会话（不影响该用户其他会话）。
- **组织与角色**：登录用户可创建组织并自动成为管理员，也可加入多个组织；
  角色仅 `admin`（管理员）与 `member`（普通成员）两种。
  - 管理员：管理成员（改角色 / 停用 / 恢复）、签发与撤销邀请、分页查询审计。
  - 普通成员：查询本组织成员名单和自己的状态。
- **访问控制**：未登录 / 会话失效 → `401 unauthorized`；
  非成员、停用成员或权限不足 → 统一 `403 forbidden`，
  对不存在的组织也返回同样的 403，不泄露组织是否存在。
- **单次邀请**：管理员为指定用户名签发绑定组织与角色的邀请，**创建满 24 小时失效**，可撤销；
  接受时严格按 ① 邀请可用性 → ② 用户名匹配 → ③ 成员状态 的顺序校验：
  - 不存在 / 已过期 / 已撤销 / 已使用 → `409 invite_unavailable`
  - 用户名不匹配 → `403 username_mismatch`
  - 已是成员（任意角色 / 状态）→ `409 already_member`，绝不覆盖角色或状态
  - 同一邀请并发接受恰好一次成功。
- **成员管理**：改角色、停用、恢复在下一次请求立即生效；停用者该组织的**所有会话**
  立即失去该组织访问权，其他组织不受影响；禁止停用 / 降级最后一个启用管理员
  （包括对自己操作）→ `409 last_admin_required`，并发降级 / 停用同样满足该约束。
- **临时委托邀请管理**：启用管理员可将本组织邀请管理临时委托给一名启用的普通成员：
  - 创建 `POST /orgs/{org_id}/delegations`（支持幂等键）：指定 `user_id` 与
    `ttl_seconds`（60–86400 的整数，否则 `422 validation_error`）；目标不存在、
    已停用或不是普通成员 → `409 ineligible_member`；同一成员最多一份有效委托，
    重复授予（含并发）→ `409 delegation_exists`；受托人角色仍为 `member`。
  - 受托人在有效期内沿用现有入口签发 `member` 邀请、撤销**凭该委托**签发的邀请；
    签发 `admin` 邀请、撤销他人或其他委托的邀请、调整成员、读审计、再委托 →
    统一 `403 forbidden`。委托不计入最后一个管理员约束；委托失效不影响已签发邀请。
  - 查询 `GET /orgs/{org_id}/delegations`：管理员见全部，普通成员仅见自己的；
    状态含 `active` / `expired` / `revoked` / `invalidated` 及原因。
    撤销 `POST /orgs/{org_id}/delegations/{id}/revoke`：仅管理员；不存在或其他组织
    → `404 not_found`；重复撤销成功且不重复记审计。
  - 到期时刻起不再授权；授予人不再是启用管理员或受托人不再是启用普通成员时，
    委托**永久失效**（`invalidated`，恢复角色也不复活），只能重新授予。
  - 委托创建 / 撤销 / 成员变化失效与受托邀请操作均入审计（含关联委托与前后状态）；
    委托签发邀请的幂等重试仍绑定原委托，原委托失效后重放返回 `403`（即使有新委托）。
- **审计**：组织、邀请、成员的每一次变更与审计行在**同一事务原子提交**，失败无部分写入；
  审计包含组织、操作者、动作、对象、时间戳及前后状态；仅本组织管理员可分页查询，
  不提供任何修改或删除接口。
- **幂等**：创建组织、签发邀请、调整成员角色 / 状态支持 `Idempotency-Key` 请求头。
  同一操作者、同一操作作用域（组织内操作还区分目标组织）、相同键 + 相同请求体
  返回首次成功结果；同键不同请求体 → `409 idempotency_conflict`；
  重试会重新校验当前权限；并发重试只产生一次业务变更和一条审计；记录持久化，重启后仍有效。

## 快速启动

需要 Python 3.11+。

```bash
./run.sh
# 服务监听 http://127.0.0.1:8000
# 可用环境变量覆盖：APP_HOST / APP_PORT / APP_DB_PATH / APP_INVITE_TTL
```

`run.sh` 首次运行会自动创建 `.venv` 并安装依赖。数据默认写入
`./data/app.db`（SQLite 文件，重启后保留）；邀请令牌重放所需的本地密钥保存在
`./data/secret.key`（权限 0600，与数据库文件分离）。

手动方式：

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
APP_DB_PATH=$(pwd)/data/app.db ./.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

健康检查：`GET /health` → `{"status":"ok"}`；交互式 API 文档在 `/docs`。

## 调用示例

所有需要登录的接口使用 `Authorization: Bearer <token>`（也支持 `X-Session-Token`）。

```bash
B=http://127.0.0.1:8000

# 1. 注册 / 登录
curl -s -X POST $B/auth/register -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Wonderland1"}'
TOK_A=$(curl -s -X POST $B/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Wonderland1"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 重复注册 -> 409 username_taken
curl -i -X POST $B/auth/register -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Whatever1"}'

# 2. 创建组织（创建者即管理员），支持幂等键
curl -s -X POST $B/orgs -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: org-1' \
  -d '{"name":"Acme"}'
# 同键同体重试返回同一结果，不产生第二条数据/审计

# 3. 准备被邀请人
curl -s -X POST $B/auth/register -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"Builder123"}'

# 4. 管理员签发绑定用户名与角色的单次邀请
INV=$(curl -s -X POST $B/orgs/1/invites -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","role":"member"}')
ITOK=$(echo "$INV" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
# 撤销：curl -X POST $B/orgs/1/invites/revoke -H "Authorization: Bearer $TOK_A" \
#   -H 'Content-Type: application/json' -d "{\"token\":\"$ITOK\"}"

# 5. 被邀请人本人登录后接受
TOK_B=$(curl -s -X POST $B/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"Builder123"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s -X POST $B/invites/accept -H "Authorization: Bearer $TOK_B" \
  -H 'Content-Type: application/json' -d "{\"token\":\"$ITOK\"}"

# 6. 查询
curl -s $B/orgs -H "Authorization: Bearer $TOK_B"                       # 我加入的组织
curl -s $B/orgs/1/members -H "Authorization: Bearer $TOK_B"             # 成员名单
curl -s $B/orgs/1/members/me -H "Authorization: Bearer $TOK_B"          # 自己的状态
curl -s "$B/orgs/1/audit?page=1&page_size=20" -H "Authorization: Bearer $TOK_A"  # 管理员审计

# 7. 管理员调整成员（2 是 bob 的 user_id；同样支持 Idempotency-Key）
curl -s -X PATCH $B/orgs/1/members/2 -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' -d '{"role":"admin"}'
curl -s -X PATCH $B/orgs/1/members/2 -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' -d '{"status":"disabled"}'   # 立即失权
curl -s -X PATCH $B/orgs/1/members/2 -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' -d '{"status":"active"}'     # 恢复

# 8. 退出（当前会话立即失效）
curl -s -X POST $B/auth/logout -H "Authorization: Bearer $TOK_A"
```

## API 一览

| 方法 | 路径 | 鉴权 | 幂等键 |
|---|---|---|---|
| POST | `/auth/register` | 无 | — |
| POST | `/auth/login` | 无 | — |
| POST | `/auth/logout` | 登录用户 | — |
| POST | `/orgs` | 登录用户 | ✔ |
| GET | `/orgs` | 登录用户 | — |
| GET | `/orgs/{org_id}/members` | 本组织启用成员 | — |
| GET | `/orgs/{org_id}/members/me` | 本组织启用成员 | — |
| POST | `/orgs/{org_id}/invites` | 本组织管理员或有效受托人（仅 member 邀请） | ✔（按组织隔离） |
| POST | `/orgs/{org_id}/invites/revoke` | 本组织管理员或签发该邀请的有效受托人 | — |
| POST | `/invites/accept` | 登录用户 | — |
| PATCH | `/orgs/{org_id}/members/{user_id}` | 本组织管理员 | ✔（按组织隔离） |
| POST | `/orgs/{org_id}/delegations` | 本组织管理员 | ✔（按组织隔离） |
| GET | `/orgs/{org_id}/delegations` | 本组织启用成员（管理员见全部，成员仅见自己） | — |
| POST | `/orgs/{org_id}/delegations/{id}/revoke` | 本组织管理员 | — |
| GET | `/orgs/{org_id}/audit?page=&page_size=` | 本组织管理员 | — |

## 错误响应

所有错误均为 JSON：

```json
{"error": {"code": "stable_code", "message": "human readable message"}}
```

| HTTP | code | 场景 |
|---|---|---|
| 401 | `unauthorized` | 未登录、会话无效 / 已退出 / 已过期 |
| 401 | `invalid_credentials` | 登录用户名或密码错误（不区分） |
| 403 | `forbidden` | 非成员 / 停用成员 / 权限不足（组织是否存在不泄露） |
| 403 | `username_mismatch` | 邀请绑定的用户名与当前登录用户不符 |
| 409 | `username_taken` | 注册用户名重复 |
| 409 | `org_name_taken` | 组织名重复 |
| 409 | `invite_unavailable` | 邀请不存在 / 过期 / 已撤销 / 已使用 / 并发竞争失败 |
| 409 | `already_member` | 已有成员再接受邀请（不覆盖角色 / 状态） |
| 409 | `last_admin_required` | 停用 / 降级最后一个启用管理员（含自我操作、并发竞争） |
| 409 | `ineligible_member` | 委托目标不存在 / 已停用 / 不是普通成员 |
| 409 | `delegation_exists` | 该成员在本组织已有一份有效委托（含并发授予） |
| 409 | `idempotency_conflict` | 同幂等键但请求体不同 |
| 404 | `not_found` / `member_not_found` | 路由不存在 / 目标成员不存在 |
| 422 | `validation_error` | 请求体不合法 |
| 500 | `internal_error` | 服务器内部错误（不泄露细节） |

## 安全说明

- 密码：PBKDF2-HMAC-SHA256，每用户独立随机盐，240000 次迭代；任何接口均不返回哈希。
- 会话令牌 / 邀请令牌：服务端只存 SHA-256 哈希，原始令牌仅在创建（及幂等重放）时返回一次；
  幂等重放所需的响应体经 Fernet 加密后入库（密钥在独立的 `secret.key` 文件中）。
- 日志：应用对所有输出安装了令牌脱敏过滤器，40/64 位十六进制令牌串不会出现在日志中
  （测试 `test_session_token_never_logged` / `test_invite_token_never_logged` 覆盖）。
- 并发：所有变更使用 `BEGIN IMMEDIATE` 单事务 + 条件 UPDATE，保证邀请单次使用、
  最后一个管理员约束在并发下成立、幂等并发重试只产生一次变更。

## 运行测试

测试通过**真实 uvicorn 子进程**发起 HTTP 请求（非内存客户端），以覆盖真实并发、
完整进程重启与磁盘持久化；原子回滚测试通过库内故障注入触发器，强制审计写入失败，
验证业务数据与审计同生共死。

```bash
./.venv/bin/python -m pytest -q
# 63 passed
```

覆盖范围：注册 / 登录 / 退出与多会话隔离、重复用户名、统一 401/403、角色权限隔离、
停用即时失权与跨组织不受影响、邀请四种不可用状态与校验顺序、并发接受仅一次成功、
已是成员不覆盖、最后管理员（含并发降级）、审计内容 / 分页 / 组织隔离 / 只读、
幂等重放 / 冲突 / 权限重校 / 并发一次变更 / 失败不缓存、事务回滚无部分写入、
明文秘密不落盘不入日志、重启后数据 / 会话 / 审计 / 幂等记录全部保留；
委托授予校验（422/409）、唯一有效委托（含并发）、受托签发 / 撤销范围与统一 403、
到期与成员变化永久失效、委托查询 / 撤销语义、委托幂等与重放绑定原委托、
委托审计与重启持久化。
