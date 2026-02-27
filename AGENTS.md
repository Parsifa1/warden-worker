# AGENTS.md（Warden Worker 代理开发手册）

本文件面向在本仓库工作的自动化编码代理（Agent）。
目标：快速理解项目、稳定实现需求、可复现验证结果。

## 1) 项目速览

- 项目：`warden-worker`
- 语言：Rust 2021 + 少量 JavaScript 路由分流
- 运行：Cloudflare Workers（WASM）+ Durable Objects
- 数据：Cloudflare D1（SQLite）
- 入口：`src/entry.js`（分流）+ `src/lib.rs`（Rust fetch/scheduled）

## 2) 关键目录与职责

- `src/core/`：认证、加密、JWT、通知、2FA、WebAuthn、错误
- `src/handlers/`：HTTP handler（Axum 风格）
- `src/models/`：请求/响应与数据库模型
- `src/router.rs`：路由集中定义
- `wrangler.jsonc`：部署、绑定、observability、构建命令

## 3) 必读文件（改动前）

1. `wrangler.jsonc`
2. `Cargo.toml`
3. `src/entry.js`
4. `src/router.rs`
5. `src/core/error.rs`
6. 对应业务的 handler/core 文件

## 4) 构建与检查命令

```bash
wrangler dev
cargo fmt
cargo fmt --check
cargo check --target wasm32-unknown-unknown
cargo clippy -- -D warnings
worker-build
worker-build --release
```

## 5) 测试命令（含单测）

仓库中已有测试（如 `src/core/webauthn.rs`、`src/core/two_factor.rs`、`src/models/cipher.rs`）。

```bash
# 全量
cargo test

# 单个测试函数（名称过滤）
cargo test test_encode_b64url

# 单个模块相关测试（路径/名称过滤）
cargo test webauthn

# 查看测试输出
cargo test -- --nocapture
```

说明：项目主目标是 WASM，但这些单测可直接在 Rust 测试框架下运行。

## 6) D1 常用命令

```bash
wrangler d1 execute vault1 --local --file=sql/schema_full.sql
wrangler d1 execute vault1 --remote --file=sql/schema_full.sql
wrangler d1 execute vault1 --local --command="SELECT * FROM users LIMIT 5"
```

## 7) 导入与模块风格

- 导入顺序：标准库 -> 第三方 -> `crate::...`
- 组间空一行，不混排
- 内部引用统一走 `crate` 根路径

## 8) 命名规范

- 文件/模块：`snake_case`
- 函数/变量：`snake_case`
- 结构体/枚举：`PascalCase`
- 常量：`SCREAMING_SNAKE_CASE`
- API 结构体常用：`#[serde(rename_all = "camelCase")]`

## 9) 类型与序列化

- 请求/响应体优先显式结构体，不滥用动态 JSON
- `Option` 字段按语义使用 `skip_serializing_if`
- 注意 D1/SQLite 布尔值与数值转换细节

## 10) Handler 约定

- HTTP handler 普遍使用 `#[worker::send]`
- 常见返回类型：`Result<Json<T>, AppError>`
- 注入状态常用：`State(env): State<Arc<Env>>`
- handler 保持薄层：校验 + 调 core + 返回结果

## 11) 错误处理规范（严格）

- 统一错误类型：`AppError`
- 优先使用：`?`、`map_err`、`ok_or_else`
- 数据库失败通常映射为 `AppError::Database`
- 认证失败通常映射为 `Unauthorized` / `BadRequest`
- 禁止吞错、禁止静默忽略关键失败

推荐模式：

```rust
let row: Option<Value> = db
    .prepare("SELECT * FROM users WHERE id = ?1")
    .bind(&[user_id.into()])?
    .first(None)
    .await
    .map_err(|_| AppError::Database)?;

let row = row.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
```

## 12) 明确禁止事项

- 业务代码中使用 `unwrap()` / `expect()`
- SQL 拼接用户输入
- 日志打印敏感信息（token/密钥/密码）
- 通过假成功掩盖错误
- 未经确认修改关键绑定配置

## 13) SQL 与查询约定

- 使用 `?1`, `?2` 参数占位符
- 常见风格：`query!` 或 `prepare().bind().run()/first()/all()`
- 列表接口避免无界查询，必要时加 `LIMIT`

## 14) 时间与 ID

- 时间字符串优先 RFC3339 UTC
- 主键/请求 ID 常用 `Uuid::new_v4().to_string()`

## 15) 路由与分流认知

- 路由在 `src/router.rs`
- `src/entry.js` 决定是否 offload 到 `HEAVY_DO`
- 高频路径要同时评估执行模型与分片策略

## 16) 变更前检查清单

1. 搜索是否已有同类实现
2. 确认影响层级（handler/core/model/router）
3. 确认是否涉及 D1 schema/migration
4. 高频路径确认是否需要 DO offload

## 17) 变更后验证清单

1. `cargo fmt --check`
2. `cargo check --target wasm32-unknown-unknown`
3. `worker-build --release`
4. 运行最小相关测试（必要时全量 `cargo test`）

## 18) 调试与日志

```bash
wrangler tail warden-worker --format json --sampling-rate 0.99
```

可结合 `jq` 过滤 `scriptVersion.id`、`cpuTime`、`executionModel`。

## 19) 安全相关提示

- 认证流程依赖 `Claims` 与 `core/jwt.rs`
- WebAuthn 逻辑位于 `core/webauthn.rs` + `handlers/webauthn.rs`
- 2FA/TOTP 位于 `core/two_factor.rs` + `handlers/two_factor.rs`
- 改认证流程时保持错误码与响应结构兼容

## 20) 性能相关提示

- 避免每请求重复执行固定高成本操作
- 轮询接口优先控制查询范围与返回大小
- 热点接口可迁移 DO，但要避免匿名流量单分片热点

## 21) Cursor / Copilot 规则整合

已检查并确认：

- `.cursor/rules/`：未发现
- `.cursorrules`：未发现
- `.github/copilot-instructions.md`：未发现

当前仓库无额外 Cursor/Copilot 指令文件。

## 22) 常见任务模板

### 新增 API

1. 在 `src/handlers/*` 增加 handler
2. 在 `src/router.rs` 注册路由
3. 必要时下沉逻辑到 `src/core/*`
4. 更新模型与 SQL（如有）
5. 运行格式化/检查/构建/测试

### 排查超时

1. 判定 `stateless` 或 `durableObject`
2. 找固定开销（重复 schema 检查、清理、无界查询）
3. 再评估是否 offload 到 `HEAVY_DO`
4. 用 tail + 统计验证效果

## 23) Agent 工作原则

1. 先证据后结论（给出文件位置）
2. 最小改动，不扩散需求
3. 风格一致（命名、错误、SQL、响应）
4. 改动后必须可验证、可复现
5. 复杂问题分阶段：定位 -> 修复 -> 验证
