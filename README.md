# Warden Worker

# 有问题？尝试 [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/parsifa1/warden-worker)

Warden Worker 是一个运行在 Cloudflare Workers 上的轻量级 Bitwarden 兼容服务端实现，使用 Cloudflare D1（SQLite）作为数据存储，核心代码用 Rust 编写，目标是"个人/家庭可用、部署成本低、无需维护服务器"。

本项目不接触你的明文密码：Bitwarden 系列客户端会在本地完成加密，服务端只保存密文数据。

> [!WARNING]
> 如果你曾经部署过旧版本并准备升级，建议在客户端导出密码库 → 重新部署本项目（全新初始化数据库）→ 再导入密码库（可显著降低迁移/兼容成本）。

## 功能

- **无服务器部署**：Cloudflare Workers + D1，零运维成本
- **兼容多端**：官方 Bitwarden（浏览器扩展 / 桌面 / 安卓）与多数第三方客户端
- **核心密码库**：注册/登录、同步、密码项（Cipher）增删改查、软删除与恢复、文件夹管理、密码库导入
- **二步验证（2FA）**：TOTP（Authenticator）、WebAuthn（通行密钥，支持 PRF 无主密码加密）
- **设备管理**：查看已登录设备、通过已登录设备给新设备授权（Auth Request 流程）
- **Send**：文本/文件 Send 的创建、访问、下载（支持最大 100MB 文件）
- **账号管理**：修改主密码、修改邮箱、头像颜色
- **官方安卓兼容**：支持 `/api/devices/knowndevice` 与 remember-device（twoFactorProvider=5）流程
- **icon 代理**：`GET /icons/{*res}` 自动获取网站图标

## 快速部署（Cloudflare）

### 0. 前置条件

- Cloudflare 账号
- Node.js + Wrangler：`npm i -g wrangler`
- Rust 工具链（建议稳定版）
- 安装 worker-build：`cargo install worker-build`

### 1. 创建 D1 数据库

```bash
wrangler d1 create vault1
```

把输出的 `database_id` 写入 `wrangler.jsonc` 的 `d1_databases`。

### 2. 初始化数据库

注意：`sql/schema_full.sql` 会 `DROP TABLE`，仅用于全新部署（会清空数据）。

```bash
wrangler d1 execute vault1 --remote --file=sql/schema_full.sql
```

`sql/schema.sql` 仅保留为历史/兼容用途；推荐新部署直接使用 `sql/schema_full.sql`。

### 3. 配置密钥（Secrets）

```bash
wrangler secret put JWT_SECRET
wrangler secret put JWT_REFRESH_SECRET
wrangler secret put ALLOWED_EMAILS
wrangler secret put TWO_FACTOR_ENC_KEY
```

- **JWT_SECRET**：访问令牌签名密钥
- **JWT_REFRESH_SECRET**：刷新令牌签名密钥
- **ALLOWED_EMAILS**：首个账号注册白名单（仅在"数据库还没有任何用户"时启用），多个邮箱用英文逗号分隔
- **TWO_FACTOR_ENC_KEY**：可选，Base64 编码的 32 字节密钥；用于加密存储 TOTP 密钥（不设置则以 `plain:` 形式存储）

### 4. 部署

```bash
wrangler deploy
```

部署后，把 Workers URL 或自定义域名（例如 `https://warden.2x.nz`）填入 Bitwarden 客户端的"自托管服务器 URL"。

## 客户端使用建议

- 官方安卓如果之前指向过其它自托管地址，建议"删除账号/清缓存后重新添加服务器"，避免 remember token 跨服务端复用导致登录失败。
- 首次启用 TOTP 后，建议在同一台设备上完成一次"输入 TOTP 登录"，后续官方安卓会自动走 remember-device（provider=5）。
- WebAuthn 通行密钥登录支持 PRF 扩展，可实现无主密码的端到端加密（客户端需支持）。

## 已实现的接口

### 配置与探测
- `GET /api/config`、`GET /api/alive`、`GET /api/now`、`GET /api/version`
- `GET /api/d1/usage`（D1 数据库用量查询）

### 认证与账号
- `POST /identity/accounts/prelogin`、`POST /api/accounts/prelogin`
- `POST /identity/accounts/register/finish`（注册）
- `POST /identity/connect/token`（登录，含 remember-device）
- `GET /api/accounts/profile`、`GET /api/accounts/revision-date`
- `POST /api/accounts/verify-password`
- `PUT /api/accounts/password`（修改主密码）
- `PUT /api/accounts/email`（修改邮箱）
- `PUT /api/accounts/avatar`（头像颜色）

### 同步
- `GET /api/sync`

### 密码项（Ciphers）
- `POST /api/ciphers/create`、`POST /api/ciphers`（创建）
- `PUT /api/ciphers/{id}`（更新）
- `PUT /api/ciphers/{id}/delete`（软删除）、`DELETE /api/ciphers/{id}`（硬删除）
- `PUT /api/ciphers/{id}/restore`（恢复）
- `PUT /api/ciphers/delete`（批量软删除）、`POST /api/ciphers/delete`（批量硬删除）
- `PUT /api/ciphers/restore`（批量恢复）
- `POST /api/ciphers/import`（密码库导入）

### 文件夹
- `POST /api/folders`（创建）
- `PUT /api/folders/{id}`（更新）
- `DELETE /api/folders/{id}`（删除）

### 二步验证（2FA）
- `GET /api/two-factor`（状态）
- `POST /api/two-factor/get-authenticator`、`POST/PUT /api/two-factor/authenticator`（TOTP）
- `PUT /api/two-factor/disable`、`DELETE /api/two-factor/authenticator`（禁用）

### WebAuthn（通行密钥）
- `GET/POST /identity/accounts/webauthn/assertion-options`（无密码登录）
- `POST /api/webauthn/attestation-options`、`POST/GET/PUT /api/webauthn`（注册管理）
- `POST /api/webauthn/assertion-options`（验证）
- `POST /api/webauthn/{id}/delete`（删除凭据）
- `POST /api/two-factor/get-webauthn`、`POST /api/two-factor/get-webauthn-challenge`（2FA WebAuthn）
- `PUT/DELETE /api/two-factor/webauthn`（2FA WebAuthn 管理）

### 设备管理与授权请求
- `GET /api/devices/knowndevice`（设备探测）
- `GET /api/devices`、`GET /api/devices/identifier/{id}`（设备列表/详情）
- `PUT/POST /api/devices/identifier/{id}/token`、`PUT/POST /api/devices/identifier/{id}/clear-token`
- `GET/POST /api/auth-requests`、`GET /api/auth-requests/pending`（Auth Request 流程）
- `GET/PUT /api/auth-requests/{id}`、`GET /api/auth-requests/{id}/response`

### Send
- `GET/POST /api/sends`（列表/创建）
- `GET/DELETE /api/sends/{send_id}`（详情/删除）
- `POST /api/sends/access/{access_id}`（访问）
- `POST /api/sends/file/v2`、`POST /api/sends/{send_id}/file/{file_id}`（文件上传，最大 100MB）
- `POST /api/sends/{send_id}/access/file/{file_id}`、`GET /api/sends/{send_id}/{file_id}`（文件下载）

### 图标
- `GET /icons/{*res}`（网站图标代理）

## 本地开发

```bash
wrangler d1 execute vault1 --local --file=sql/schema_full.sql
wrangler dev
```

本地可用 `.dev.vars`（Wrangler 支持）注入 secrets：

```
JWT_SECRET=your_secret
JWT_REFRESH_SECRET=your_refresh_secret
ALLOWED_EMAILS=test@example.com
TWO_FACTOR_ENC_KEY=base64_encoded_32_bytes
```

## 数据库迁移

如从旧版本迁移，可在 `sql/migrations/` 找到增量迁移脚本，按日期顺序执行：

```bash
wrangler d1 execute vault1 --remote --file=sql/migrations/20260220_split_webauthn_usage.sql
```

建议新部署始终使用 `sql/schema_full.sql` 全量初始化。

## 许可证

MIT
