# AGENTS.md - Warden Worker 开发指南

本文档为 AI 代码助手提供 Warden Worker 项目的开发规范和约定。

## 项目概述

Warden Worker 是运行在 Cloudflare Workers 上的 Bitwarden 兼容服务端，使用 Rust 编写，Cloudflare D1（SQLite）作为数据存储。

**技术栈**：
- 语言：Rust (edition 2021)
- 运行时：Cloudflare Workers (wasm32-unknown-unknown)
- 框架：Axum + worker crate
- 数据库：Cloudflare D1 (SQLite)
- 构建工具：worker-build
- 部署工具：wrangler

**项目结构**：
```
src/
├── core/           # 核心功能（auth, crypto, db, error, jwt, two_factor, webauthn）
├── handlers/       # API 处理器（accounts, ciphers, devices, folders, identity, sync 等）
├── models/         # 数据模型（user, cipher, folder, send, sync）
├── router.rs       # Axum 路由定义
├── notifications.rs # Durable Objects 通知系统
└── lib.rs          # 入口点
```

---

## 构建和测试命令

### 本地开发

```bash
# 初始化本地数据库
wrangler d1 execute vault1 --local --file=sql/schema_full.sql

# 启动本地开发服务器
wrangler dev

# 使用 .dev.vars 文件注入环境变量（本地开发）
# 创建 .dev.vars 文件并添加：
# JWT_SECRET=your_secret
# JWT_REFRESH_SECRET=your_refresh_secret
# ALLOWED_EMAILS=test@example.com
# TWO_FACTOR_ENC_KEY=base64_encoded_32_bytes
```

### 构建

```bash
# 开发构建
worker-build

# 生产构建（优化）
worker-build --release
```

### 部署

```bash
# 部署到 Cloudflare Workers
wrangler deploy

# 配置 Secrets（生产环境）
wrangler secret put JWT_SECRET
wrangler secret put JWT_REFRESH_SECRET
wrangler secret put ALLOWED_EMAILS
wrangler secret put TWO_FACTOR_ENC_KEY
```

### 数据库操作

```bash
# 远程数据库初始化（警告：会清空数据）
wrangler d1 execute vault1 --remote --file=sql/schema_full.sql

# 执行迁移脚本
wrangler d1 execute vault1 --remote --file=sql/migrations/20260216_add_avatar_color.sql

# 本地数据库查询
wrangler d1 execute vault1 --local --command="SELECT * FROM users LIMIT 5"
```

### 代码质量检查

```bash
# Rust 格式化检查
cargo fmt --check

# 应用格式化
cargo fmt

# Clippy lint 检查
cargo clippy -- -D warnings

# 编译检查（不生成 wasm）
cargo check --target wasm32-unknown-unknown
```

**注意**：项目当前没有单元测试。添加测试时使用 `cargo test`。

---

## 代码风格指南

### 导入组织

按以下顺序组织导入，组之间用空行分隔：

```rust
// 1. 标准库
use std::sync::Arc;
use std::convert::TryFrom;

// 2. 外部 crate（按字母顺序）
use axum::{extract::State, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{query, Env};

// 3. 内部模块（使用 crate::）
use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::models::user::User;
```

### 命名约定

- **模块**：snake_case（`two_factor.rs`, `auth.rs`）
- **结构体/枚举**：PascalCase（`AppError`, `Claims`, `CipherData`）
- **函数/变量**：snake_case（`get_sync_data`, `user_id`）
- **常量**：SCREAMING_SNAKE_CASE（`JWT_SECRET`）
- **保留字段**：使用 `r#` 前缀（`r#type`）

### 错误处理

**使用 `AppError` 枚举统一错误类型**：

```rust
use crate::error::AppError;

// 函数签名
pub async fn handler(claims: Claims, State(env): State<Arc<Env>>) -> Result<Json<Value>, AppError>

// 错误传播
let db = db::get_db(&env)?;  // Worker 错误自动转换
let user: User = query!(&db, "SELECT * FROM users WHERE id = ?1", user_id)
    .map_err(|_| AppError::Database)?  // 显式转换数据库错误
    .first(None)
    .await?
    .ok_or(AppError::NotFound("User not found".to_string()))?;  // Option 转 Result

// 自定义错误
return Err(AppError::BadRequest("Invalid input".to_string()));
return Err(AppError::Unauthorized("Invalid token".to_string()));
```

**禁止**：
- 空的 `catch` 块
- 使用 `unwrap()` 或 `expect()`（除非在测试或初始化代码中）
- 忽略错误（使用 `let _ = ...` 除非有充分理由）

### 类型和序列化

**结构体定义**：

```rust
// API 请求/响应使用 camelCase
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub email: String,
    pub master_password_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_password_hint: Option<String>,
    #[serde(default)]
    pub kdf_iterations: Option<i32>,
}

// 数据库模型
#[derive(Debug, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    #[serde(with = "bool_from_int")]  // SQLite 布尔值转换
    pub email_verified: bool,
    pub created_at: String,
}
```

**SQLite 布尔值处理**：

D1 数据库将布尔值存储为整数（0/1），需要自定义序列化：

```rust
#[serde(with = "bool_from_int")]
pub email_verified: bool,

// 或使用自定义 deserializer
#[serde(deserialize_with = "deserialize_bool_from_int")]
pub favorite: bool,
```

### 异步函数

**Handler 函数使用 `#[worker::send]` 宏**：

```rust
#[worker::send]
pub async fn profile(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    // 实现
}
```

**内部辅助函数**：

```rust
async fn get_cipher_dbmodel(
    env: &Arc<Env>,
    cipher_id: &str,
    user_id: &str,
) -> Result<CipherDBModel, AppError> {
    // 实现
}
```

### 数据库查询

**使用 `query!` 宏（推荐）**：

```rust
use worker::query;

let user: User = query!(&db, "SELECT * FROM users WHERE id = ?1", user_id)
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("User not found".to_string()))?;
```

**使用 `prepare` + `bind`**：

```rust
let folders: Vec<Folder> = db
    .prepare("SELECT * FROM folders WHERE user_id = ?1")
    .bind(&[user_id.into()])?
    .all()
    .await?
    .results()?;
```

**参数绑定**：
- 使用 `?1`, `?2` 占位符（从 1 开始）
- 避免字符串拼接（防止 SQL 注入）

### 时间处理

```rust
use chrono::Utc;

// 生成 ISO 8601 时间戳
let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

// 解析时间
let time = chrono::DateTime::parse_from_rfc3339(&user.created_at)
    .map_err(|_| AppError::Internal)?
    .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
```

### UUID 生成

```rust
use uuid::Uuid;

let id = Uuid::new_v4().to_string();
```

### 日志

```rust
// 初始化（在 lib.rs 中）
console_error_panic_hook::set_once();
let _ = console_log::init_with_level(log::Level::Debug);

// 使用
log::info!("User {} logged in", user_id);
log::warn!("Cannot parse {err:?} {cipher:?}");
log::error!("Worker error: {}", e);
```

---

## 架构模式

### 路由定义

在 `router.rs` 中使用 Axum 路由：

```rust
Router::new()
    .route("/api/sync", get(sync::get_sync_data))
    .route("/api/ciphers/create", post(ciphers::create_cipher))
    .route("/api/ciphers/{id}", put(ciphers::update_cipher).delete(ciphers::hard_delete_cipher))
    .with_state(app_state)
```

### 认证

使用 `Claims` 提取器自动验证 JWT：

```rust
pub async fn handler(claims: Claims, State(env): State<Arc<Env>>) -> Result<Json<Value>, AppError> {
    let user_id = claims.sub;  // 已验证的用户 ID
    // ...
}
```

### 环境变量和 Secrets

```rust
// 获取 Secret
let jwt_secret = env.secret("JWT_SECRET")?;

// 获取 D1 数据库
let db = env.d1("vault1").map_err(AppError::Worker)?;
```

### 响应格式

返回 JSON 使用 `Json` 包装器：

```rust
Ok(Json(json!({
    "id": user.id,
    "email": user.email,
    "object": "profile"
})))
```

---

## 安全注意事项

1. **密码验证**：使用 `constant_time_eq` 防止时序攻击
   ```rust
   use constant_time_eq::constant_time_eq;
   
   if !constant_time_eq(hash1.as_bytes(), hash2.as_bytes()) {
       return Err(AppError::Unauthorized("Invalid password".to_string()));
   }
   ```

2. **JWT 验证**：检查 `exp`（过期时间）和 `nbf`（生效时间）

3. **SQL 注入**：始终使用参数化查询，禁止字符串拼接

4. **敏感数据**：不在日志中输出密码、token、密钥

---

## 常见任务

### 添加新的 API 端点

1. 在 `src/handlers/` 创建或修改处理器函数
2. 在 `src/router.rs` 添加路由
3. 如需新数据模型，在 `src/models/` 定义
4. 更新数据库 schema（如需要）

### 数据库迁移

1. 在 `sql/migrations/` 创建迁移文件（格式：`YYYYMMDD_description.sql`）
2. 使用 `wrangler d1 execute` 执行迁移
3. 更新 `sql/schema_full.sql`（用于全新部署）

### 调试

1. 使用 `log::debug!()` 添加日志
2. 本地运行 `wrangler dev` 查看实时日志
3. 生产环境在 Cloudflare Dashboard 查看 Workers 日志

---

## 禁止事项

- ❌ 使用 `panic!()`, `unwrap()`, `expect()`（除非在初始化代码）
- ❌ 忽略错误（使用 `?` 或显式处理）
- ❌ SQL 字符串拼接
- ❌ 在日志中输出敏感信息
- ❌ 硬编码密钥或凭证
- ❌ 修改 `wrangler.jsonc` 中的 `database_id`（使用 Secrets 或环境变量）

---

## 参考资源

- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)
- [worker-rs GitHub](https://github.com/cloudflare/workers-rs)
- [Axum 文档](https://docs.rs/axum/)
- [Bitwarden API 文档](https://bitwarden.com/help/api/)
