# warden-worker

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/parsifa1/warden-worker)
[![Powered by Cloudflare](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white)](https://www.cloudflare.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

跑在 Cloudflare Workers 上的 Bitwarden 兼容服务端。Rust 写的，D1 存数据，不需要自己维护服务器。

> [!IMPORTANT]
> 服务端看不到你的明文密码。Bitwarden 客户端在本地加密，服务端只存密文。

## 为什么做这个

不想自己维护服务器，Vaultwarden 虽然好用，但机器挂了或者忘续费，密码就没了。

## 功能

- 注册/登录、密码库同步、Cipher / Folder 增删改查
- TOTP、WebAuthn（含 PRF 流程）
- 设备管理、授权请求（官方客户端 remember-device 流程）
- Send（文本/文件，最大 100MB）
- 图标代理（Worker 侧直接代理，不走 DO，7 天缓存 + 负缓存）
- CPU 密集接口走 `HEAVY_DO` offload，通知走 `NOTIFICATIONS_HUB`

## 兼容性

测试可用：官方 Bitwarden 浏览器扩展、Android、iOS。

## 部署

### 准备

- Cloudflare 账号
- Node.js + `npm i -g wrangler`
- Rust stable 工具链 + `cargo install worker-build`

### 步骤

**1. 创建 D1**

```bash
wrangler d1 create vault1
```

把返回的 `database_id` 填进 `wrangler.jsonc` 的 `d1_databases`。

**2. 初始化数据库**

> [!WARNING]
> `schema_full.sql` 会清空重建所有表，只在全新部署时用。

```bash
wrangler d1 execute vault1 --remote --file=sql/schema_full.sql
```

**3. 设置 Secrets**

```bash
wrangler secret put JWT_SECRET
wrangler secret put JWT_REFRESH_SECRET
wrangler secret put ALLOWED_EMAILS
wrangler secret put TWO_FACTOR_ENC_KEY
```

| 变量 | 说明 |
|------|------|
| `JWT_SECRET` | 访问令牌签名密钥 |
| `JWT_REFRESH_SECRET` | 刷新令牌签名密钥 |
| `ALLOWED_EMAILS` | 注册白名单，库里无用户时生效 |
| `TWO_FACTOR_ENC_KEY` | 可选，Base64 编码 32 字节密钥 |

**4. 部署**

```bash
wrangler deploy
```

把 Worker 域名填到 Bitwarden 客户端的"自托管服务器地址"就行。

## 本地开发

```bash
wrangler d1 execute vault1 --local --file=sql/schema_full.sql
wrangler dev
```

`.dev.vars` 里注入本地 secrets：

```
JWT_SECRET=your_secret
JWT_REFRESH_SECRET=your_refresh_secret
ALLOWED_EMAILS=test@example.com
TWO_FACTOR_ENC_KEY=base64_encoded_32_bytes
```

## 数据库迁移

新部署直接用 `sql/schema_full.sql`。升级时按顺序跑 `sql/migrations/` 下的增量文件：

```bash
wrangler d1 execute vault1 --remote --file=sql/migrations/20260220_split_webauthn_usage.sql
```

## 常用命令

```bash
cargo fmt --check
cargo check --target wasm32-unknown-unknown
cargo clippy -- -D warnings
worker-build --release
cargo test
```

## 说明

**图标代理**：`/icons/*` 在 `entry.js` 直接处理，不走 HEAVY_DO。成功图标缓存 7 天，404/5xx 短缓存+回退默认图标，减少打上游次数。

**限流**：`LOGIN_RATE_LIMITER` 默认 `100 req/60s`，改 `wrangler.jsonc` 里的配置。

**Durable Objects**：DO 的 CPU 预算是 30s/请求（远高于外层 Worker 的 10ms），适合 import、登录等 CPU 密集场景。免费计划每天 10 万次请求额度，日常够用。

## 许可证

MIT
