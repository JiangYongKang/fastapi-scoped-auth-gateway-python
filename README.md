# FastAPI Scoped Local Auth Gateway

一套**仅依赖本地进程内存储**的接口鉴权层。支持两类凭证、统一有序的判定链路、
按凭证限流，以及旧静态凭证的平滑迁移。不依赖任何数据库或外部服务，重启后状态清空，
适合作为网关侧鉴权逻辑的参考实现与本地演练。

## 目录结构

```
auth_gateway/
  config.py        # 全部配置项（环境变量可覆盖）
  clock.py         # 时间抽象（SystemClock / 测试用 FixedClock）
  errors.py        # 可区分的失败原因 DenyReason 与异常类型
  models.py        # API Key / 访问令牌 / 刷新令牌 / 凭证族 数据模型
  crypto.py        # 凭证生成、解析、盐值哈希、恒定时间校验
  storage.py       # 线程安全的本地存储 + 原子化刷新令牌轮换
  ratelimit.py     # 按凭证的固定时间窗限流
  migration.py     # 旧静态凭证迁移窗口控制
  authorization.py # 基于 scope 的默认拒绝判定
  audit.py         # 结构化审计日志（输入 + 判定依据）
  issuer.py        # 凭证签发、刷新轮换、吊销
  service.py       # 认证 -> 授权 -> 限流 的统一编排（链路核心）
  dependencies.py  # FastAPI 依赖：require_scope(...)
  routes_admin.py  # 签发 / 刷新 / 吊销 接口
  routes_gateway.py# 受保护的示例资源接口
  app.py           # 组装组件、异常到响应的映射
tests/             # 覆盖重放、并发、权限、限流、迁移窗口的测试
```

路由层保持轻量：所有判定都在 `service.AuthService` 与各职责模块中，不堆叠在单个路由函数里。

## 凭证类型与生命周期

### 1. API Key（`ak_<id>.<secret>`）

- 签发时绑定一组权限范围（scopes）与有效期；密钥明文仅在签发响应中返回一次，存储的是盐值哈希。
- 可被吊销；到达 `expires_at` 后失效。
- 在**资源访问边缘**，「不存在 / 密钥错误 / 已吊销 / 已过期」对外统一返回
  `invalid_credential`，避免攻击者据此判断凭证状态；真实原因只写入服务端审计日志。

### 2. 短时令牌：访问令牌 + 刷新令牌（凭证族）

- 访问令牌（`at_...`）短时有效（默认 15 分钟），携带 scopes。
- 刷新令牌（`rt_...`）长时有效（默认 7 天），属于一个**凭证族（family）**，
  族在签发时绑定 scopes，轮换后保持不变。
- **刷新令牌轮换（rotation）**：每次刷新，旧刷新令牌被消费（`consumed`），
  同时签发新的访问令牌与新的刷新令牌。
- **重放检测**：同一个刷新令牌被重复或并发使用时：
  - 只有第一次呈现成功；之后的呈现返回 `refresh_reuse_detected`；
  - 一旦检测到重放，**整个凭证族立即失效**，此前已轮换出的新令牌也返回
    `refresh_family_revoked`。
  - 校验—消费—挂接新令牌在存储层的**单把锁内原子完成**，因此并发刷新不可能出现两次成功。
- 失败原因可区分：`invalid_credential`（无法识别）、`expired_token`（自然过期、未重放）、
  `refresh_reuse_detected`（重放）、`refresh_family_revoked`（族已被株连吊销）。
  其中「重放」的判断优先于「过期」——任何年龄的重放都是攻击信号。

## 权限模型（默认拒绝）

- 没有声明任何 scope 的凭证默认什么都不能访问。
- scope 为字面量精确匹配，不做通配/隐含，判定过程简单可解释。
- 受保护接口通过依赖声明所需 scope：`Depends(require_scope("read:profile"))`。

资源访问边缘有四类**可区分**结果：

| 状态码 | error code              | 含义                                   |
|-------:|-------------------------|----------------------------------------|
| 401    | `missing_credential`    | 未携带凭证                             |
| 401    | `invalid_credential`    | 凭证无法识别 / 过期 / 已吊销（不区分） |
| 401    | `insufficient_scope`    | 凭证有效但权限不足                     |
| 429    | `rate_limited`          | 超出该凭证的限额                       |

错误响应只包含稳定的 `error` 与泛化的 `error_description`，不回显凭证、
不暗示其他资源或凭证是否存在。

### 限流

- 按凭证维度的**固定时间窗**计数（默认每 60 秒 100 次）。
- 判定顺序为：认证 → 权限 → 限流。**缺少凭证、凭证无效、权限不足的请求一律不消耗配额**，
  只有通过认证与授权后才占用一个名额。

### 存储异常处理

- 存储层抛出 `StorageError` 时，全局异常处理器记录真实堆栈到服务端日志，
  对客户端只返回 `500 {"error":"internal_error"}`，不泄露内部细节。

## 旧凭证迁移策略

迁移期内，存量静态凭证（非 `前缀_id.secret` 形态）仍可使用，但受限并可观测：

- 仅当 `now < AUTH_MIGRATION_ENDS_AT` 时接受；窗口结束的瞬间起**彻底失效**，
  之后时间只增不减，决策只会翻转一次，不会出现「同一凭证时好时坏」。
- 迁移期内旧凭证只被授予固定的低权限 scope（默认 `read:public`）。
- 每次放行都带明确的可观察标记：审计字段 `legacy=true` 与
  `migration_marker="legacy-credential-migration"`，响应体中 `legacy=true`。
- 窗口关闭后，资源边缘统一返回 `invalid_credential`（不泄露凭证存在性），
  但审计中保留真实原因 `legacy_revoked_post_window` 以便排查。

## 配置项（均可用环境变量覆盖）

| 环境变量                    | 默认值          | 说明                               |
|----------------------------|----------------|------------------------------------|
| `AUTH_ACCESS_TOKEN_TTL`    | `900`          | 访问令牌有效期（秒）               |
| `AUTH_REFRESH_TOKEN_TTL`   | `604800`       | 刷新令牌有效期（秒，7 天）         |
| `AUTH_API_KEY_TTL`         | `7776000`      | API Key 默认有效期（秒，90 天）    |
| `AUTH_RATE_LIMIT`          | `100`          | 每凭证每窗口请求配额               |
| `AUTH_RATE_WINDOW`         | `60`           | 限流窗口长度（秒）                 |
| `AUTH_MIGRATION_ENDS_AT`   | `0`            | 迁移窗口结束的 Unix 时间戳（秒）   |
| `AUTH_LEGACY_SCOPE`        | `read:public`  | 迁移期旧凭证被授予的 scope（逗号分隔） |

旧静态凭证集合在通过 `create_app(..., legacy_keys={...})` 装配应用时注入。

## 本地验证

```bash
# 1. 安装依赖（uv）
uv sync --extra dev        # 或：uv sync && uv add --dev pytest httpx

# 2. 运行测试（含输入与判定依据的 INFO 级审计日志）
uv run pytest

# 3. 启动服务
uv run python main.py
#  -> http://127.0.0.1:8000  （文档 /docs，健康检查 /health）
```

手动演练：

```bash
# 签发 API Key
curl -s -X POST http://127.0.0.1:8000/auth/api-keys \
  -H 'Content-Type: application/json' \
  -d '{"scopes":["read:public","read:profile"]}'

# 签发访问/刷新令牌对
curl -s -X POST http://127.0.0.1:8000/auth/tokens \
  -H 'Content-Type: application/json' -d '{"scopes":["read:profile"]}'

# 用刷新令牌轮换（再执行一次即触发重放，整个族失效）
curl -s -X POST http://127.0.0.1:8000/auth/refresh \
  -H 'Content-Type: application/json' -d '{"refresh_token":"<rt_...>"}'

# 携带凭证访问
curl -s http://127.0.0.1:8000/profile -H 'Authorization: Bearer <at_...>'
```

## 测试覆盖

- `tests/test_refresh_replay.py`：单次使用、重放株连、过期区分、未知凭证、8 线程并发仅一次成功。
- `tests/test_scopes_and_ratelimit.py`：默认拒绝、权限不足、限流边界、被拒绝不耗配额、按凭证独立计数、吊销/过期统一表现。
- `tests/test_migration_window.py`：窗口内低权限放行与迁移标记、窗口结束即彻底失效、同一时刻判定稳定不抖动。
- `tests/test_error_separation.py`：四类边缘原因可区分、响应不泄密、存储异常映射为通用 500。

每个用例都会通过 `logging` 打印**输入**与**判定依据**；审计日志以单行 JSON 输出，
包含凭证类型、凭证 id、所需/已授 scope、决策、原因、迁移标记、剩余配额等字段。
