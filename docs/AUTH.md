# 鉴权层设计说明

## 1. 凭证生命周期

### API Key（长期凭证）

- 签发：`POST /auth/api-keys`，body `{"scopes": [...], "ttl_seconds": 60}`。
  返回 `api_key = "<key_id>.<secret>`；服务端只保存 secret 的
  PBKDF2-HMAC-SHA256 哈希（随机 salt，200k 轮）。
- 携带：请求头 `X-API-Key: <key_id>.<secret>`。
- 有效期：默认 90 天；`ttl_seconds` 可覆盖，签发时传空/0 语义为永不过期；
  过期判定基于 UTC。
- 吊销：`POST /auth/revoke/api-key {"key_id": "..."}`，记录被标记 revoked，
  之后认证返回 `revoked_credential`。
- 认证检查顺序：存在性/密钥校验 → revoked → expired，保证三类原因互不混淆。

### 短时令牌（access + refresh）

- 签发：`POST /auth/tokens {"scopes": [...]}`，为每个调用方建立一个
  **凭证族（family）**，同时返回 access token 与 refresh token。
  服务端只保存两者的 SHA-256 摘要（令牌本身高熵，无需慢哈希）。
- access token：默认 15 分钟，放在 `Authorization: Bearer ...`。
- refresh token：默认 7 天，仅用于 `POST /auth/refresh`。

#### 轮换与重放检测（refresh token rotation + reuse detection）

每次刷新：

1. 按摘要查到 refresh token；查不到 → `invalid_credential`。
2. 已过期 → `expired_credential`。
3. 所属 family 已吊销 → 按家族死因区分：
   - 重放导致的家族失效 → `reuse_detected`；
   - 管理端主动吊销 → `revoked_credential`。
4. 原子“比较并消费”（`consume_refresh_token` 在存储锁内完成）：
   - 恰好第一个调用消费成功，签发同 family 的**新一对**令牌；
   - 任何并发或重复调用拿到的都是 `False` →
     判定为重放，**整个 family 立即吊销**（该族现存 refresh/access 全部失效），
     返回 `reuse_detected`。

因此“同一 refresh token 并发使用只有一次成功”由存储层原子性保证；
重放后即使攻击者手里握的是刚轮换出的新令牌，也无法再使用。

- 主动吊销：`POST /auth/revoke/family {"family_id": "..."}`。

## 2. 权限模型

- 凭证携带一组 scope 字符串；受保护路由用
  `Depends(require_scopes("read:items", ...))` 声明所需范围。
- **默认拒绝（default deny）**：
  - 未声明任何 scope 的凭证无法签发；
  - 所需 scope 必须全部包含才放行，缺少任意一个即 `insufficient_scope`(403)；
  - 401 类失败（缺凭证/无效/过期/吊销/重放/旧凭证失效）与 403 权限不足、
    429 超限在 HTTP 状态码与错误码两个维度都可区分。
- 判定顺序固定为 **认证 → 授权 → 限流**：
  - 未通过认证/授权的请求**不进入限流器**，因此拒绝不消耗正常额度；
  - 错误响应只包含稳定的泛化信息（如 `"permission denied"`），
    不回显缺失的 scope 名称，也不区分“凭证不存在/密钥错误”，
    避免泄露其他凭证或资源是否存在。

## 3. 限流

- 维度：按凭证身份（API Key 的 `key_id`、令牌族的 `family_id`、
  旧凭证的 identifier）分别计数，互不影响。
- 算法：存储层的滑动日志窗口（窗口外时间戳被清除），到达上限后拒绝为
  `rate_limited`(429)；被拒绝的命中不落盘，不占用后续额度。

## 4. 旧凭证迁移

- 旧静态凭证形如 `identifier:secret`，通过请求头
  `X-Legacy-Credential`（可配置）携带。
- 迁移窗口 = `AUTH_MIGRATION_ENABLED=true` 且当前时间 <
  `AUTH_MIGRATION_ENDS_AT`（未配置结束时间则窗口常开）。窗口判定是
  **关于时钟的纯函数**，切换过程不会出现同一凭证时而通过时而拒绝。
- 窗口内：
  - 密钥恒定时间校验通过后，旧凭证被解析为**低权限** Principal，
    只拥有 `AUTH_LEGACY_SCOPES`（默认仅 `read:public`），
    访问高权限接口会正常得到 `insufficient_scope`；
  - 每次成功使用都留下可观察标记：响应头 `X-Auth-Legacy: true`、
    服务端日志，以及 `GET /internal/metrics` 中
    `legacy_credential.accepted / last_accepted_identity` 计数。
- 窗口结束后：同凭证一律 `legacy_disabled`(401)，
  并累计 `rejected_expired_window`；开关关闭或时间到达即彻底失效，
  不依赖逐个删除配置。
- 主凭证（API Key / Bearer）不受迁移窗口影响。

## 5. 错误处理边界

- 所有业务拒绝都抛出携带 `DenyReason` 的 `AuthError`，由统一异常处理器
  映射为状态码 + `{"error":{"code","message"}}`，并按原因计数到
  `/internal/metrics`。
- 认证、授权/限流、签发三处都把存储层异常兜底为
  `internal_error`(500)，异常文本（地址、堆栈等）不会进入响应体；
  后端故障默认按失败关闭处理，不会被当成放行。

## 6. 本地验证方法

```bash
# 启动
python main.py

BASE=http://localhost:8000

# 签发 API Key 并访问
KEY=$(curl -s -XPOST $BASE/auth/api-keys -H 'Content-Type: application/json' \
  -d '{"scopes":["read:items"]}' | python -c 'import sys,json;print(json.load(sys.stdin)["api_key"])')
curl -s $BASE/items -H "X-API-Key: $KEY"

# 短时令牌刷新重放演示
TOK=$(curl -s -XPOST $BASE/auth/tokens -H 'Content-Type: application/json' \
  -d '{"scopes":["read:items"]}')
RT=$(echo "$TOK" | python -c 'import sys,json;print(json.load(sys.stdin)["refresh_token"])')
curl -s -XPOST $BASE/auth/refresh -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT\"}"
curl -s -XPOST $BASE/auth/refresh -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT\"}"
# -> 401 reuse_detected，整个 family 失效

# 观察拒绝原因与旧凭证计数
curl -s $BASE/internal/metrics
```

迁移窗口演练（窗口在 2026-09-30 12:00 UTC 结束）：

```bash
AUTH_MIGRATION_ENDS_AT=2026-09-30T12:00:00+00:00 python main.py
# 窗口前：200 + X-Auth-Legacy: true
curl -si $BASE/public -H 'X-Legacy-Credential: legacy-static-key:legacy-static-secret'
# 将系统时间/结束时间调到过去后：401 legacy_disabled，且结果稳定
```

自动化测试：

```bash
python3 -m pytest -q
```

覆盖：刷新重放与 8 路并发刷新、过期/吊销/重放原因区分、默认拒绝与
权限不足、限流边界（第 N、N+1 个请求；拒绝不计额度；按凭证隔离）、
迁移窗口前后的旧凭证行为与稳定性，以及存储异常不透出。
测试开启了 `log_cli`，日志中会打印每个用例的输入和判定依据。

## 7. 本地存储说明与局限

实现为单进程内存存储（`InMemoryStore`，单把 `RLock` 保证原子性），
重启后数据清空，适合本地验证与单进程部署。存储接口
（`CredentialStore` Protocol）已隔离，后续可替换为 SQLite/Redis 等实现，
而无需改动 service / 路由层。
