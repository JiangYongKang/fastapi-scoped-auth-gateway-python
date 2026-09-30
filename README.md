# FastAPI Scoped Auth Gateway（本地存储版）

一套只依赖进程内本地存储的接口鉴权层，支持两类凭证：

- **API Key**：长期凭证，可绑定权限范围（scopes）与有效期，可吊销。
- **短时令牌**：access token（默认 15 分钟）+ refresh token（默认 7 天），
  refresh token 每次使用即**轮换**，并带有**重放检测**：同一个 refresh token
  被并发或重复使用时，只有一次成功，其余请求被拒绝且整个凭证族（family）
  立即整体失效。

拒绝原因全部以稳定的错误码区分（`error.code`），不区分时不泄露其他凭证
或资源是否存在；被拒绝的请求不消耗限流额度；存储层异常不会透出到响应。

## 快速开始

```bash
# Python 3.14+，依赖仅 fastapi（测试用 pytest/httpx）
uv sync            # 或 pip install fastapi uvicorn pytest httpx pytest-asyncio
python main.py     # 启动 uvicorn
```

本地验证（详见 [`docs/AUTH.md`](docs/AUTH.md) 的完整演练脚本）：

```bash
# 1) 签发短时令牌
curl -s -X POST localhost:8000/auth/tokens \
  -H 'Content-Type: application/json' \
  -d '{"scopes":["read:items"]}'

# 2) 携带 access token 访问
curl -s localhost:8000/items -H "Authorization: Bearer <access_token>"

# 3) 刷新（轮换）
curl -s -X POST localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' -d '{"refresh_token":"<refresh_token>"}'

# 4) 迁移期内使用旧静态凭证（低权限，响应带 X-Auth-Legacy: true）
curl -si localhost:8000/public -H 'X-Legacy-Credential: legacy-static-key:legacy-static-secret'
```

运行测试（日志会打印每个用例的输入与判定依据）：

```bash
python3 -m pytest
```

## 错误码（失败原因可区分）

| code                     | HTTP | 含义                                   |
|--------------------------|------|----------------------------------------|
| `missing_credential`     | 401  | 未提供任何凭证                         |
| `invalid_credential`     | 401  | 凭证非法/未知/格式错误                 |
| `expired_credential`     | 401  | 凭证已过期                             |
| `revoked_credential`     | 401  | 凭证被主动吊销                         |
| `reuse_detected`         | 401  | refresh token 重放，凭证族已整体失效   |
| `legacy_disabled`        | 401  | 迁移窗口已结束，旧凭证彻底失效         |
| `insufficient_scope`     | 403  | 已认证但权限不足（默认拒绝）           |
| `rate_limited`           | 429  | 超出凭证限额                           |
| `internal_error`         | 500  | 后端异常（详情不出服务边界）           |

## 配置项（环境变量，前缀 `AUTH_`）

| 变量                                  | 默认值                  | 说明                                   |
|---------------------------------------|-------------------------|----------------------------------------|
| `AUTH_ACCESS_TOKEN_TTL_SECONDS`       | `900`                   | access token 有效期（秒）              |
| `AUTH_REFRESH_TOKEN_TTL_SECONDS`      | `604800`                | refresh token 有效期（秒）             |
| `AUTH_API_KEY_DEFAULT_TTL_SECONDS`    | `7776000`（90 天，0=永不过期） | 签发 API Key 的默认有效期       |
| `AUTH_RATE_LIMIT_WINDOW_SECONDS`      | `60`                    | 限流窗口长度（秒）                     |
| `AUTH_RATE_LIMIT_MAX`                 | `100`                   | 窗口内每凭证最大请求数                 |
| `AUTH_MIGRATION_ENABLED`              | `true`                  | 旧凭证迁移总开关                       |
| `AUTH_MIGRATION_ENDS_AT`              | 未设置（窗口常开）      | 迁移结束时间：unix 时间戳或 ISO-8601   |
| `AUTH_LEGACY_SCOPES`                  | `read:public`           | 旧凭证在迁移期内被授予的低权限范围     |
| `AUTH_LEGACY_CREDENTIALS`             | 内置一组演示凭证        | JSON：`{"identifier":"secret"}`       |
| `AUTH_LEGACY_HEADER`                  | `X-Legacy-Credential`   | 携带旧凭证的请求头                     |

## 目录结构

```
app/
  config.py          配置（环境变量）
  errors.py          拒绝原因枚举 + AuthError
  models.py          凭证记录 / Principal
  security.py        随机生成、PBKDF2/SHA-256、恒定时间比较
  storage.py         本地存储协议 + 线程安全内存实现（含原子轮换、滑动窗口限流）
  ratelimit.py       按凭证限流
  migration.py       旧凭证解析 + 迁移指标
  service.py         凭证生命周期 + 认证/授权/限流判定链
  dependencies.py    FastAPI 依赖：提取凭证 -> 认证 -> 授权 -> 限流
  routes_auth.py     签发/刷新/吊销接口
  routes_protected.py 示例受保护资源
  routes_observability.py 迁移与拒绝原因计数
tests/               重放/并发、权限、限流边界、迁移窗口前后等测试
docs/AUTH.md         凭证生命周期、权限模型、迁移策略详述
```
