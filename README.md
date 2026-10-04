# Team Access Platform

基于 HTTP 的组织成员与权限管理服务。FastAPI + SQLite（WAL、文件持久化、原子事务）。

## 功能概览

- **账号 / 会话**：唯一用户名 + 密码注册、登录、退出；用户名重复返回 `409`；
  密码使用 PBKDF2-HMAC-SHA256 加盐哈希存储，永不明文落盘或出现在任何响应中；
  退出立即吊销当前会话（不影响该用户其他会话）。
  `POST /auth/logout-others`（请求体 `current_password`）保留当前会话、
  吊销同账号其他所有有效会话并返回 `{"revoked_sessions":N}`（不含当前会话、
  已退出或已过期会话）；未加入组织、被停用或移除的账号同样可用；
  密码错误返回 `403 invalid_current_password`，任何失败都不吊销会话。
- **组织与角色**：登录用户可创建组织并自动成为管理员，也可加入多个组织；
  角色仅 `admin`（管理员）与 `member`（普通成员）两种。
  创建以**真正执行时**携带的会话状态为准：会话在请求进入写事务前被退出、
  被“退出其他会话”或修改密码撤销、或恰好到期（到期时刻即无效），即使请求
  刚到达时仍然登录有效，也统一 `401 unauthorized`，不产生组织、创建者管理员
  成员关系或 `org.created` 审计；同一账号的其他有效会话不能替代本次请求的
  会话。组织成功创建后会话才失效的，创建结果保留。
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
  单人调整 `PATCH /orgs/{org_id}/members/{user_id}` 以**真正执行时**携带的会话状态
  为准：会话在请求进入写事务前被退出、被“退出其他会话”或修改密码撤销、或恰好到期
  （到期时刻即无效），即使请求刚到达时仍然登录有效、且账号仍是启用管理员，也统一
  `401 unauthorized`，目标成员的角色 / 状态 / 更新时间保持原样，不失效任何委托，
  不产生成员变更或委托失效审计；同一账号的其他有效会话不能替代本次请求的会话，仅
  撤销其他会话而保留本次会话时调整正常成功；Bearer 与 X-Session-Token 两种登录方式
  规则相同。该 401 优先于组织权限不足（403）、目标成员不存在（404）、最后管理员
  限制（409）与幂等冲突（409）。携带 Idempotency-Key 的首次调整与已有成功结果的重试
  都受当前会话约束：会话失效时不返回缓存的成员信息、不改写或删除原成功记录，首次被
  拒绝不占用键，重新登录后可用原键原请求继续操作。调整成功提交后会话才失效的，已完成
  的成员变化与审计保留。
- **成员移除**：`DELETE /orgs/{org_id}/members/{user_id}` 由本组织**启用管理员**调用
  （可移除启用 / 停用成员，也可移除自己），成功返回 `200` 及
  `{"org_id","user_id","removed":true}`。与停用 / 恢复（保留成员关系）不同，移除会
  **删除成员关系**：目标立即从成员名单和自己的组织列表消失，其所有会话下一次访问该
  组织按非成员拒绝；账号、会话及其他组织关系不受影响。权限不足或组织不存在统一 `403`，
  目标不属于本组织 `404 member_not_found`，移除最后一名启用管理员（含自己、并发竞争）
  → `409 last_admin_required`。恢复 / 单人 / 批量调整均不能让已移除者回来（单人 `404`，
  批量涉及已移除者整批 `404` 且不改变其他成员）。移除后凭**新邀请**可重新加入，角色
  由新邀请决定、加入时间重新记录。
  - 目标作为授予人或受托人的有效委托**永久失效**（沿用 `grantor_not_admin` /
    `delegate_ineligible` 原因），重新加入不复活。
  - 本组织移除前签发、仍可使用且**绑定目标用户名**的邀请同时撤销，接受时仍先检查
    邀请可用性 → `409 invite_unavailable`；目标此前签发给其他人的邀请沿用原规则。
  - 成员移除、邀请撤销、委托失效、审计与幂等结果在**同一事务原子提交**。
  - 支持 `Idempotency-Key`，独立作用域（与单人 / 批量调整互不占键）；同键同目标重放
    首次结果（目标重新加入后也不会再次移除），同键换目标 → `409 idempotency_conflict`，
    重试重新校验权限（自我移除后的重放为 `403`），失败不占键。
- **批量成员管理**：`PATCH /orgs/{org_id}/members/batch` 一次提交 1–100 项调整
  （每项正整数 `user_id` 且至少给 `role`/`status` 之一，未给字段保持原值）；
  仅本组织**启用管理员**可调用（受托人无权），非成员 / 组织不存在统一 `403`，
  目标不属于本组织整批 `404 member_not_found`。所有成员修改、委托失效与审计在
  **同一事务**内原子提交，任何一项失败不留部分修改；同批“提升一人 + 降级 / 停用
  原管理员”与列表顺序无关均可成功，最终无启用管理员则 `409 last_admin_required`，
  允许发起者降级 / 停用自己且立即按新身份失权。未变化成员照样返回但不更新
  `updated_at`、不记审计；响应含批次标识 `batch_id`，`members` 按提交顺序返回最终
  成员信息，成员变更与委托失效审计均带该标识。成员变化引起的委托**永久失效**与
  整批修改同时生效，恢复成员不复活旧委托；同一委托的授予人与受托人同时失去资格时
  只记**一条**失效记录并并列两种原因，此前已签发邀请仍按原规则使用。
  批量调整同样以**真正执行时**携带的会话状态为准，与单人调整完全一致：合法请求
  等待其他写操作期间，会话被退出、被“退出其他会话”或修改密码撤销、或恰好到期
  （到期时刻即无效），即使请求刚到达时仍然登录有效、且账号仍是启用管理员，也统一
  `401 unauthorized`，整批不改变任何目标成员的角色 / 状态 / 更新时间，不失效任何
  委托，不产生成员变更或委托失效审计，不返回成员信息或批次结果；同一账号的其他
  有效会话不能替代本次请求的会话，仅撤销其他会话而保留本次会话时批次正常成功；
  Bearer 与 X-Session-Token 两种登录方式规则相同。该 401 优先于组织权限不足
  （403）、目标成员不存在（整批 404）、最后管理员限制（409）与幂等冲突（409），
  请求内容校验及 422 行为不变。携带 Idempotency-Key 的首次提交与已有成功结果的
  重试都受当前会话约束：会话失效时不返回缓存的批次结果、不改写或删除原成功记录，
  首次被拒绝不占用键，重新登录后可用原键原请求提交，有效会话下的正常重试仍返回
  原批次结果而不重复修改或记审计。批次成功提交后会话才失效的，已完成的成员变化
  与审计保留。
- **审计**：组织、邀请、成员的每一次变更与审计行在**同一事务原子提交**，失败无部分写入；
  审计包含组织、操作者、动作、对象、时间戳、前后状态及批量操作的共同 `batch_id`；
  仅本组织管理员可分页查询，不提供任何修改或删除接口。
  - `GET /orgs/{org_id}/audit/scan` 在游标分批读取的基础上支持首批传 `batch_id`
    （1–128 字符，原值精确匹配，不去空格 / 不转大小写；空串 / 超长 → 422
    `validation_error`），只返回本组织属于该批次的成员变更与委托失效记录；
    不传则查询本组织全部审计。无匹配（含标识只存在于其他组织）一律
    `200 {items:[], total:0, next_cursor:null}`，不透露其他组织信息。
  - 筛选条件固化在游标内：后续只传游标即沿用；同时传 `batch_id` 必须与首次完全一致，
    换批次、给未筛选查询追加条件（含升级前签发的旧游标）→ 422 `invalid_cursor`；
    快照范围在首批固定，之后新增的同批次记录不进入本次查询，重新发起无游标请求才能看到。
    每批都重新校验当前组织启用管理员资格，游标不替代授权。
- **临时委托邀请管理**：启用管理员可指定本组织一名**启用的普通成员**为受托人，
  将邀请管理交托对方一段有限时间（`60..86400` 秒的整数）。受托人在有效期内沿用
  现有邀请入口签发 **member** 邀请，并可撤销自己凭这份委托签发的邀请；不能签发
  admin 邀请、撤销他人或其他委托签发的邀请、调整成员、读取审计或继续委托。
  委托**不计入**最后一个管理员约束，受托人角色仍为 `member`；委托失效不撤销此前
  签发的邀请。授予人不再是启用管理员，或受托人不再是启用普通成员时，委托**永久失效**
  （恢复角色/状态也不能复活，只能重新授予）。管理员可查询/撤销本组织全部委托，
  受托人只能查询自己的委托。
- **幂等**：创建组织、签发邀请、调整成员角色 / 状态、批量调整成员、移除成员、创建委托
  支持 `Idempotency-Key` 请求头。
  同一操作者、同一操作作用域（组织内操作还区分目标组织；批量与单人入口使用各自
  独立作用域，互不占键）、相同键 + 相同请求体返回首次成功结果；同键不同请求体 →
  `409 idempotency_conflict`；单人调整与移除的目标不在请求体中（单人正文只有
  角色 / 状态，移除无正文），因此成功使用的键还绑定首次成功请求的**目标成员**：
  同一作用域下用原键换另一名成员（即使正文完全相同、或新目标不属于该组织）→
  `409 idempotency_conflict`，不返回首次成员信息、不执行新调整；原键原目标原正文
  仍重放首次结果，成员后来的正常变化不被重放覆盖；首次请求即使只是设置成已有状态
  （无实际变化）也算成功使用并绑定目标。重试会重新校验当前权限（自我降级后的批量重试返回
  `403`；委托签发邀请的幂等重试仍由原委托授权，原委托失效后返回 `403`，即使已有
  新委托）；并发重试只产生一次业务变更和一条审计；失败不占用键；记录持久化，
  重启后仍有效。
  创建组织的幂等以**本次请求携带的会话**在执行写事务时仍然有效为前提：
  等待期间会话失效（退出 / 退出其他会话 / 修改密码 / 到期）时，即使键已对应一个
  成功结果也返回 `401 unauthorized`，不返回组织信息、不改写原成功记录；尚未成功
  使用的键不被此次拒绝占用，重新登录后可用同键同请求继续创建；会话无效时统一
  返回 `unauthorized`，优先于 `org_name_taken` 与 `idempotency_conflict`。

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

# 7b. 批量调整（1–100 项；支持 Idempotency-Key，与单人入口互不占键）
curl -s -X PATCH $B/orgs/1/members/batch -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: batch-1' \
  -d '{"changes":[{"user_id":2,"role":"member"},{"user_id":3,"status":"disabled"}]}'
# -> {"batch_id":"b_...","members":[...最终成员信息，按提交顺序...]}

# 7c. 移除成员（删除成员关系；停用/恢复仍保留关系，移除不保留）
curl -s -X DELETE $B/orgs/1/members/2 -H "Authorization: Bearer $TOK_A" \
  -H 'Idempotency-Key: remove-1'
# -> {"org_id":1,"user_id":2,"removed":true}
# 最后一名启用管理员（含自己）-> 409 last_admin_required；目标不在本组织 -> 404

# 8. 退出（当前会话立即失效）
curl -s -X POST $B/auth/logout -H "Authorization: Bearer $TOK_A"

# 8b. 退出其他会话（保留当前会话，结束同账号其他设备登录；需当前密码）
curl -s -X POST $B/auth/logout-others -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' -d '{"current_password":"Wonderland1"}'
# -> {"revoked_sessions":N}

# 9. 临时委托邀请管理（受托人仍是普通成员，不计入最后管理员约束）
# 9a. 管理员授予：bob 可在 3600 秒内签发 member 邀请
BOB_ID=$(curl -s $B/orgs/1/members -H "Authorization: Bearer $TOK_A" \
  | python3 -c 'import sys,json;print(next(m["user_id"] for m in json.load(sys.stdin)["members"] if m["username"]=="bob"))')
DEL=$(curl -s -X POST $B/orgs/1/delegations -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: deleg-1' \
  -d "{\"user_id\":$BOB_ID,\"duration_seconds\":3600}")
DEL_ID=$(echo "$DEL" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
# 9b. 受托人沿用现有入口签发 member 邀请（role 必须是 member）
TOK_B=$(curl -s -X POST $B/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"Builder123"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s -X POST $B/orgs/1/invites -H "Authorization: Bearer $TOK_B" \
  -H 'Content-Type: application/json' \
  -d '{"username":"carol","role":"member"}'
# 9c. 受托人只能撤销自己凭这份委托签发的邀请；admin 邀请 / 他人邀请 → 403
# 9d. 管理员查询全部委托（受托人只看自己的）
curl -s $B/orgs/1/delegations -H "Authorization: Bearer $TOK_A"
# 9e. 管理员撤销委托（重复撤销成功，不重复记录审计）
curl -s -X POST $B/orgs/1/delegations/$DEL_ID/revoke -H "Authorization: Bearer $TOK_A"
```

## API 一览

| 方法 | 路径 | 鉴权 | 幂等键 |
|---|---|---|---|
| POST | `/auth/register` | 无 | — |
| POST | `/auth/login` | 无 | — |
| POST | `/auth/logout` | 登录用户 | — |
| POST | `/auth/logout-others` | 登录用户（不要求组织成员身份） | — |
| POST | `/orgs` | 登录用户 | ✔ |
| GET | `/orgs` | 登录用户 | — |
| GET | `/orgs/{org_id}/members` | 本组织启用成员 | — |
| GET | `/orgs/{org_id}/members/me` | 本组织启用成员 | — |
| POST | `/orgs/{org_id}/invites` | 本组织管理员 **或** 有效受托人 | ✔（按组织隔离） |
| POST | `/orgs/{org_id}/invites/revoke` | 本组织管理员 **或** 签发该邀请的受托人 | — |
| POST | `/invites/accept` | 登录用户 | — |
| PATCH | `/orgs/{org_id}/members/batch` | 本组织管理员（受托人不可） | ✔（按组织隔离，独立作用域） |
| PATCH | `/orgs/{org_id}/members/{user_id}` | 本组织管理员 | ✔（按组织隔离） |
| DELETE | `/orgs/{org_id}/members/{user_id}` | 本组织管理员 | ✔（按组织隔离，独立作用域） |
| POST | `/orgs/{org_id}/delegations` | 本组织管理员 | ✔（按组织隔离） |
| GET | `/orgs/{org_id}/delegations` | 本组织启用成员（管理员看全部，受托人只看自己） | — |
| POST | `/orgs/{org_id}/delegations/{delegation_id}/revoke` | 本组织管理员 | — |
| GET | `/orgs/{org_id}/audit?page=&page_size=` | 本组织管理员 | — |
| GET | `/orgs/{org_id}/audit/scan?cursor=&batch_id=&page_size=` | 本组织管理员 | — |

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
| 409 | `last_admin_required` | 停用 / 降级 / 移除最后一个启用管理员（含自我操作、批量整批判定、并发竞争） |
| 409 | `ineligible_member` | 委托目标不存在 / 已停用 / 不是普通成员 |
| 409 | `delegation_exists` | 同一组织同一成员已有一份有效委托（含并发授予） |
| 409 | `idempotency_conflict` | 同幂等键但请求体不同，或单人调整 / 移除中同键换了目标成员（含目标不属于本组织） |
| 404 | `not_found` / `member_not_found` | 路由不存在 / 目标成员不存在（调整或移除单人目标不属于本组织；批量中任一目标不属于本组织则整批 404） |
| 422 | `validation_error` | 请求体不合法（含批量数量越界、重复成员、缺少调整字段）；审计扫描的 `batch_id` 空串 / 超长、`page_size` 越界 |
| 422 | `invalid_cursor` | 审计扫描游标伪造 / 损坏 / 属于其他组织，或续批时改变 / 追加 `batch_id` 筛选条件 |
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
# 238 passed
```

覆盖范围：注册 / 登录 / 退出与多会话隔离、重复用户名、统一 401/403、角色权限隔离、
停用即时失权与跨组织不受影响、邀请四种不可用状态与校验顺序、并发接受仅一次成功、
已是成员不覆盖、最后管理员（含并发降级）、审计内容 / 分页 / 组织隔离 / 只读、
幂等重放 / 冲突 / 权限重校 / 并发一次变更 / 失败不缓存、事务回滚无部分写入、
明文秘密不落盘不入日志、重启后数据 / 会话 / 审计 / 幂等记录全部保留。
创建组织按执行时会话授权：等待期间退出 / 退出其他会话 / 修改密码 / 恰好到期
（含同账号其他会话仍有效、Bearer 与 X-Session-Token 两种头）→ 401 且不留组织 /
管理员关系 / 审计；幂等首建与重放均须会话有效，401 不占键、不改写成功记录、
优先于重名与幂等冲突；先成功后失效保留结果。

单人成员调整按执行时会话授权：等待期间退出 / 退出其他会话 / 修改密码 / 恰好到期
（含同账号其他会话仍有效、仅撤销其他会话时正常成功、Bearer 与 X-Session-Token
两种头）→ 401 且成员角色 / 状态 / 更新时间原样、委托不失效、无成员变更与委托
失效审计；幂等首次调整与成功重放均须会话有效，401 不返回缓存成员信息、不占键、
不改写成功记录，优先于 403 / 404 / 最后管理员 / 幂等冲突；先成功后退出保留变化
与审计。

批量成员调整同样按执行时会话授权（与单人入口同一机制与判定顺序）：等待期间退出 /
退出其他会话 / 修改密码 / 恰好到期（含同账号其他会话仍有效、仅撤销其他会话时
正常成功、Bearer 与 X-Session-Token 两种头）→ 401 且全部目标成员角色 / 状态 /
更新时间原样、委托不失效、无成员变更与委托失效审计、不返回成员信息或批次结果；
幂等首次提交与成功重放均须会话有效，401 不返回缓存批次结果、不占键、不改写成功
记录，优先于 403 / 整批 404 / 最后管理员 / 幂等冲突，422 内容校验行为不变；
先成功后失效保留整批变化与审计。

委托专项：创建校验（60..86400 整数）、目标资格（不存在 / 停用 / 非普通成员 →
`ineligible_member`）、重复有效委托（`delegation_exists`，含并发）、受托人签发
member 邀请与撤销本人邀请、越权（admin 邀请 / 他人邀请 / 调成员 / 读审计 / 再委托）
统一 403、列表可见性（管理员看全部 / 受托人只看自己）、四种状态（有效 / 到期 /
撤销 / 成员变化失效）及原因、重复撤销成功不重复审计、到期边界即时失权、授予人或
受托人资格永久失效（恢复不复活）、委托签发邀请的幂等重试仍由原委托授权、并发授予
唯一有效、并发撤销与邀请的串行化语义、重启后委托 / 失效状态 / 幂等结果保留、
审计原子回滚。

批量成员专项：提交顺序返回、未给字段保持原值、未变化成员不更新时间不记审计、
数量越界 / 重复成员 / 缺调整字段 / 非法取值 422、受托人无权与统一 403、
跨组织目标整批 404 且零修改、最后管理员整批顺序无关判定（提升 + 降级互换、
自我降级立即失权重试 403）、委托双方同时失格只产生一条并列双原因的失效记录、
恢复不复活旧委托、已签发邀请不受影响、成员与委托审计共享 `batch_id`、
批量幂等重放 / 冲突 / 失败不占键 / 与单人入口键隔离 / 并发单次变更、
批量与单人及受托人邀请并发下不留零名启用管理员且失效委托不能再签发邀请、
故障注入下成员 / 委托 / 审计 / 幂等整体回滚、重启后结果与幂等记录保留、
批量按执行时会话授权（等待期间退出 / 退出其他会话 / 修改密码 / 恰好到期，
含同账号其他会话仍有效、仅撤销其他会话正常成功、Bearer 与 X-Session-Token
两种头）→ 401 且全部目标原样 / 委托不失效 / 无审计、幂等首提与成功重放均须
会话有效且 401 不占键不改写记录不返回缓存批次结果、优先于 403 / 404 / 最后
管理员 / 幂等冲突而 422 不变、先成功后失效保留整批结果。

成员移除专项：200 响应与名单 / 组织列表消失、所有会话下次访问按非成员拒绝、
账号 / 会话 / 其他组织不受影响、可移除停用成员与自己（保留第二名启用管理员时）、
权限不足 / 组织不存在统一 403、目标不属于本组织 404、最后启用管理员（含自己、
含对方为停用管理员）409、停用管理员无权移除、恢复 / 单人 / 批量不能复活已移除者
（批量整批 404 且不改动其他成员）、绑定目标用户名的可用邀请撤销且接受仍先判可用性
409、已用 / 已过期邀请不被改写、目标签发他人的邀请继续可用、新邀请重新加入（新角色、
加入时间重记，同一秒内也能区分签发与移除先后）、委托授予人 / 受托人永久失效且重入不
复活、失效委托不能再签发邀请、移除审计含操作者 / 目标 / 时间 / 移除前角色与状态 /
邀请与委托变化且不含令牌、幂等同键重放（重新加入后也不二次移除）/ 同键换目标 409 /
与单人及批量和其他组织作用域隔离 / 自我移除重试 403 / 失败不占键 / 并发单次变更、
并发同目标与交叉移除及与批量调整 / 邀请接受串行化（不留零名启用管理员）、故障注入下
成员删除 / 邀请撤销 / 委托失效 / 审计 / 幂等整体回滚、重启后移除状态 / 审计 / 幂等
结果保留。
