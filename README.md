# 组织成员与权限管理 API

一个可通过 HTTP 使用的组织成员与权限管理服务。数据落盘 SQLite，**重启后不丢失**；
密码使用 bcrypt 哈希存储，会话与邀请令牌均为随机数、仅存 SHA-256 摘要，日志不记录令牌。

- 语言/栈：Python 3 标准库（`http.server` + `sqlite3`）+ `bcrypt`，无外部 Web 框架
- 持久化：单 SQLite 文件（WAL 模式），每次写操作在 `BEGIN IMMEDIATE` 事务内提交，
  业务数据、审计、幂等记录**原子提交**，失败无部分写入
- 并发：写事务串行化 + 条件更新，邀请并发接受仅一次成功；降级/停用最后一个启用管理员
  （含并发）被拒绝
- 认证：`Authorization: Bearer <token>`；未登录/会话失效 → `401`
- 授权：非成员、停用成员、权限不足、组织不存在，统一返回 `403 org_access_denied`，
  不泄露组织是否存在

---

## 一、环境要求

- Python 3.10+（开发环境为 3.12）
- Python 包：`bcrypt`（`pip install bcrypt`，多数系统已自带）

无需数据库服务器，SQLite 随 Python 内置。

---

## 二、启动

```bash
pip install bcrypt          # 若未安装
python3 server.py --host 127.0.0.1 --port 8080 --db data.db
```

服务默认监听 `127.0.0.1:8080`，数据写入 `data.db`（WAL 模式会附带 `data.db-wal` /
`data.db-shm`，属正常现象）。重启进程后数据仍然保留。

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--host` | `127.0.0.1` | 监听地址 |
| `--port` | `8080` | 监听端口 |
| `--db` | `data.db` | SQLite 数据库文件路径 |

健康检查：

```bash
curl -s http://127.0.0.1:8080/healthz
# {"status":"ok"}
```

> 调小 bcrypt 轮数可加快测试速度（仅测试用）：`BCRYPT_ROUNDS=4 python3 server.py ...`

---

## 三、快速上手（curl 示例）

下面用 `$TOKEN` / `$ATOKEN` 等保存登录返回的令牌。

### 1. 注册与登录

```bash
# 注册（用户名唯一，重复返回 409 username_exists）
curl -s -X POST http://127.0.0.1:8080/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"secret123"}'
# {"user_id":1,"username":"alice"}

# 登录（返回会话令牌）
curl -s -X POST http://127.0.0.1:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"secret123"}'
# {"token":"<TOKEN>","user_id":1,"username":"alice"}
TOKEN=<上一步返回的 token>

# 当前登录用户
curl -s http://127.0.0.1:8080/api/me -H "Authorization: Bearer $TOKEN"
# {"user_id":1,"username":"alice"}

# 退出（立即失效）
curl -s -X POST http://127.0.0.1:8080/api/auth/logout -H "Authorization: Bearer $TOKEN"
# {"logged_out":true}
```

### 2. 创建组织（创建者即管理员）

```bash
curl -s -X POST http://127.0.0.1:8080/api/orgs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: org-create-001' \
  -d '{"name":"Acme"}'
# {"org":{"id":1,"name":"Acme","role":"admin","status":"active"}}

# 我的组织列表
curl -s http://127.0.0.1:8080/api/orgs -H "Authorization: Bearer $TOKEN"
```

### 3. 邀请与接受邀请

管理员为指定用户名签发绑定组织与角色的单次邀请（24 小时有效，可撤销）：

```bash
# 管理员签发邀请（返回的 token 仅此一次可见）
curl -s -X POST http://127.0.0.1:8080/api/orgs/1/invites \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: invite-bob-001' \
  -d '{"username":"bob","role":"member"}'
# {"invite":{"id":1,"token":"<INVITE_TOKEN>","username":"bob","role":"member",
#   "status":"pending","created_at":"...","expires_at":"..."}}
ITOKEN=<invite.token>

#  bob 先注册/登录
curl -s -X POST http://127.0.0.1:8080/api/auth/register \
  -H 'Content-Type: application/json' -d '{"username":"bob","password":"bobpass123"}'
BTOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"bob","password":"bobpass123"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# bob 接受邀请（加入组织）
curl -s -X POST http://127.0.0.1:8080/api/invites/accept \
  -H "Authorization: Bearer $BTOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$ITOKEN\"}"
# {"org_id":1,"org_name":"Acme","role":"member","status":"active"}

# 管理员查看邀请列表（不含令牌本身）
curl -s http://127.0.0.1:8080/api/orgs/1/invites -H "Authorization: Bearer $TOKEN"

# 撤销邀请
curl -s -X POST http://127.0.0.1:8080/api/orgs/1/invites/1/revoke \
  -H "Authorization: Bearer $TOKEN"
```

### 4. 成员管理（仅管理员）

```bash
# 成员名单（管理员与普通成员均可查看）
curl -s http://127.0.0.1:8080/api/orgs/1/members -H "Authorization: Bearer $TOKEN"

# 调整角色（升级/降级）
curl -s -X PATCH http://127.0.0.1:8080/api/orgs/1/members/2 \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: role-bob-001' \
  -d '{"role":"admin"}'

# 停用成员（下一次请求立即失权；不影响其在其他组织的访问）
curl -s -X POST http://127.0.0.1:8080/api/orgs/1/members/2/disable \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: disable-bob-001'

# 恢复成员
curl -s -X POST http://127.0.0.1:8080/api/orgs/1/members/2/enable \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: enable-bob-001'
```

### 5. 审计查询（仅管理员，分页）

```bash
curl -s "http://127.0.0.1:8080/api/orgs/1/audit?limit=20" \
  -H "Authorization: Bearer $TOKEN"
# {"items":[{"id":...,"action":"member.disable","actor_id":1,"actor_username":"alice",
#   "target_type":"member","target_id":"2",
#   "before":{"status":"active"},"after":{"status":"disabled"},
#   "created_at":"..."}],"next_cursor":20}

# 翻页：带上一页返回的 next_cursor
curl -s "http://127.0.0.1:8080/api/orgs/1/audit?limit=20&cursor=20" \
  -H "Authorization: Bearer $TOKEN"
```

审计只提供查询，无修改/删除接口（`DELETE` 返回 `404`）。

---

## 四、幂等性（Idempotency-Key）

以下接口支持 `Idempotency-Key` 请求头：

| 操作 | 接口 | 作用域 |
| --- | --- | --- |
| 创建组织 | `POST /api/orgs` | 全局（按操作者） |
| 签发邀请 | `POST /api/orgs/{id}/invites` | 目标组织 |
| 调整角色 | `PATCH /api/orgs/{id}/members/{uid}` | 目标组织 |
| 停用/恢复 | `POST /api/orgs/{id}/members/{uid}/disable\|enable` | 目标组织 |
| 撤销邀请 | `POST /api/orgs/{id}/invites/{iid}/revoke` | 目标组织 |

规则：

- 同一操作者 + 同一操作 + 相同键 + 相同请求体 → 返回**首次成功结果**（不重复写入）
- 同键但请求体不同 → `409 idempotency_conflict`
- 组织内操作还区分目标组织：不同组织可用相同键
- 重试会**重新校验当前权限**：权限被收回后重试返回 `403`，而非缓存的成功结果
- 并发重试只产生一次业务变更与一条审计；记录持久化，**重启后仍有效**

---

## 五、错误码

所有错误均为 JSON：`{"error":{"code":"<稳定错误码>","message":"..."}}`

| HTTP | code | 含义 |
| --- | --- | --- |
| 400 | `bad_request` | 请求格式/参数错误 |
| 401 | `unauthorized` | 未登录或会话失效 |
| 401 | `invalid_credentials` | 用户名或密码错误 |
| 403 | `org_access_denied` | 非成员/停用成员/权限不足/组织不存在（统一返回，不泄露组织存在性） |
| 403 | `invite_username_mismatch` | 邀请绑定的用户名与当前登录用户不一致 |
| 404 | `not_found` | 路由或成员不存在 |
| 409 | `username_exists` | 用户名已被注册 |
| 409 | `invite_unavailable` | 邀请不存在/已过期/已撤销/已使用 |
| 409 | `already_member` | 已是该组织成员（不覆盖角色或状态） |
| 409 | `last_admin_required` | 禁止停用或降级最后一个启用管理员（含自我操作、并发操作） |
| 409 | `idempotency_conflict` | 幂等键已被不同请求使用 |
| 500 | `internal_error` | 服务内部错误 |

---

## 六、关键行为说明

- **邀请校验顺序**：先校验邀请可用性（存在/未过期/未撤销/未使用）→ 再校验用户名匹配
  → 最后校验成员状态。不存在、过期、撤销或已使用的邀请返回 `409 invite_unavailable`；
  用户名不匹配返回 `403 invite_username_mismatch`。
- **邀请有效期**：签发后 24 小时内有效，过期自动失效（列表中标记为 `expired`）。
- **单次使用**：同一邀请并发接受仅一次成功；已有成员接受返回 `409 already_member`，
  不覆盖其角色或状态。
- **最后管理员保护**：降级或停用会使组织没有启用管理员时被拒绝（`409 last_admin_required`），
  包括管理员对自己的操作；并发降级/停用同样满足该约束。
- **即时失权**：停用在**下一次请求**即生效，被停用者所有会话都失去该组织访问权，
  但不影响其在其他组织的访问；降级同理。
- **审计**：记录组织、操作者、动作、对象、时间、前后状态；仅管理员可查询，按组织分页。
- **日志**：只记录 `uid 方法 路径 -> 状态 耗时`，不记录令牌、密码或请求体。

---

## 七、自动化测试

测试以子进程方式启动真实服务（独立 SQLite 文件），覆盖正常流程、隔离、并发、
即时失权、回滚与重启后重试：

```bash
python3 -m unittest tests.test_api -v
```

覆盖用例（部分）：

- 重复用户名 `409`、错误密码 `401`、未登录 `401`
- 密码不落盘明文（读取 db + WAL 校验）
- 组织隔离：非成员/停用/越权统一 `403`，且与「组织不存在」错误码一致
- 邀请校验顺序、撤销、过期、并发接受仅一次成功
- 角色调整幂等、最后管理员保护（含并发降级）
- 停用即时失权且不影响其他组织、已停用再停用为 no-op
- 登出立即失效
- 审计内容完整性与分页、无修改/删除接口
- 并发幂等重试只产生一次变更与一条审计
- **重启后**数据保留、会话仍有效、幂等重试返回首次结果、新写入正常
- 幂等键冲突不产生任何写入；失败的邀请接受不产生成员关系
- 幂等重试重新校验当前权限（权限收回后重试返回 `403`）
