# warden-worker 代码审查报告

- 审查类型：只读静态审查（未修改任何源码）
- 审查范围：`src/` 全量 + `sql/` + `wrangler.jsonc`
- 运行环境约束：Cloudflare Workers（Rust→WASM，非 DO 路径 10ms CPU 上限、单线程、内存受限）+ Durable Objects + D1（SQLite，逐语句往返）
- 日期：2026-06-15

## 总体定性

核心路径（CRUD / sync / 登录）SQL 全部参数化、口令比较走 constant-time、WebAuthn 签名拼接（`authData ‖ SHA-256(clientDataJSON)` + P-256 DER 验签）方向正确，项目基本可用。

但存在 **1 个未鉴权信息泄露 + DoS 接口**、**多处认证重放 / 撤销缺口**，以及 **若干热路径性能放大**。合并生产前应优先处理 Critical / High。

| 严重度 | 数量 |
|--------|------|
| Critical | 1 |
| High | 8 |
| Medium | 10 |
| Low | 8 |

---

## Critical

### C1 — `/api/d1/usage` 完全无鉴权，可匿名全表扫描

- 位置：`src/handlers/usage.rs:34-38`、`src/handlers/usage.rs:42-175`、`src/router.rs:224`
- 问题：handler 签名仅 `State(env)` + `Query(q)`，**没有 `Claims` 提取器**；`user_id` 是任意 query 参数，**省略它即走 `None` 分支**，对 `ciphers / sends / send_files / send_file_chunks / folders / devices / two_factor_authenticator / users` 全表执行 `SUM(LENGTH(...))`。
- 影响：
  1. 任意匿名者可读取全库及任意指定 `user_id` 的存储用量（信息泄露）。
  2. 该路径不在 `HEAVY_DO_PREFIXES`，走 10ms CPU 普通 Worker，多表全扫极易撞 CPU 上限（DoS）。
- 建议：加 `Claims` 鉴权，强制 `user_id == claims.sub`；删除无界全表（`None`）分支。

---

## High

### 安全

#### H1 — JWT 未绑定 security stamp，撤销语义缺失
- 位置：`src/core/auth.rs:13-25`、`src/handlers/identity.rs`（refresh 分支 ~752）、`src/handlers/accounts.rs:584`
- 问题：`Claims` 无 `security_stamp` / `jti` / 会话版本字段。改密 / 改邮箱更新了 `users.security_stamp`，但 `Claims` 提取器与 refresh 分支从不比对。
- 影响：改密后旧 refresh token 在 30 天有效期内仍可换取新 access token，无法真正注销会话。
- 建议：将 security stamp / session version 纳入 access/refresh claims，并在提取器与 refresh 分支按用户当前值校验，或改为服务端存储/轮换 refresh token。

#### H2 — auth-request 登录可重放
- 位置：`src/handlers/identity.rs:369-389`、`src/handlers/devices.rs:49`
- 问题：校验 `approved` + `access_code_hash` 后直接发 token，**不要求 `authentication_date IS NULL`，登录成功后也不消费该请求**。
- 影响：同一已批准 auth-request 的 access code 在 TTL 内可反复重放换取新 token。
- 建议：成功登录时条件更新 `authentication_date` / 删除请求，并只接受未消费请求。

#### H3 — TOTP 种子可明文入库
- 位置：`src/core/two_factor.rs:97-106`
- 问题：`TWO_FACTOR_ENC_KEY` 缺失时 `encrypt_secret_with_optional_key` 以 `plain:{secret}` 前缀明文存储；调用方 `env.secret("TWO_FACTOR_ENC_KEY").ok()` 吞掉缺失配置。
- 影响：D1 一旦泄露，所有 TOTP 种子明文暴露，2FA 全部失效。
- 建议：生产路径强制要求加密密钥，缺失时报错而非明文回退。

#### H4 — Passwordless WebAuthn challenge 非一次性消费
- 位置：`src/core/webauthn.rs:986-1006`
- 问题：仅校验签名 JWT 内的 challenge/origin/rpId/signature，未像普通 2FA 那样服务端取出并删除 nonce；零计数器 passkey 下 `old_sign_count > 0 && new_sign_count > 0` 的回退检测失效。
- 影响：截获一次 passwordless 登录提交，可在 5 分钟 JWT TTL 内重复换取会话。
- 建议：为 passwordless challenge 增加服务端 nonce/jti 存储并在验证时原子删除。

#### H5 — Passwordless 登录不强制 User Verification
- 位置：`src/core/webauthn.rs:1031-1043`、`src/core/webauthn.rs:1290`
- 问题：主登录路径 `parse_auth_data` 只拒绝缺少 `flags & 0x01`（UP），不检查 `flags & 0x04`（UV）。
- 影响：无密码登录退化为"持有安全钥匙即可登录"，丢失/被恶意触发的未受 PIN/生物识别保护 authenticator 可直接换取完整会话。
- 建议：challenge options 用 `userVerification: "required"`，验证时强制 `flags & 0x04 != 0`。

### 性能

#### H6 — `/api/sync` 全量无界读取
- 位置：`src/handlers/sync.rs:42-70`
- 问题：folders / ciphers / sends 全部 `SELECT * ... WHERE user_id = ?1`，无 LIMIT / 游标。
- 影响：每次全量读 + 反序列化 + 序列化，复杂度随 vault 线性增长；移动端轮询/重试重复支付。这是最重读路径。
- 建议：实现增量同步 / 修订游标；对超大 vault 返回可恢复的分段响应。

#### H7 — Send 文件全量入内存
- 位置：`src/handlers/sends.rs:490-522`（上传）、`src/handlers/sends.rs:794-814`（下载）
- 问题：上传只用客户端声明的 `fileLength` 决定内联/分块，**不累计实际字节**；下载把所有分块拼成完整 base64 字符串再解码，峰值 ≥2.3× 文件大小。
- 影响：Workers 内存/CPU 风险，几十 MB 文件即可 OOM / CPU 超限；上传可被未受限输入放大。
- 建议：读取时累计原始字节并设硬上限；下载按 chunk 流式读取/解码/响应，或改用 R2 存内容、D1 仅存元数据。

#### H8 — 每请求 schema self-healing DDL
- 位置：`src/core/webauthn.rs:145-222`（`ensure_webauthn_tables`）、`src/handlers/devices.rs:856-870`（`ensure_auth_requests_table`）
- 问题：每次请求都跑 `CREATE TABLE IF NOT EXISTS` / `ALTER TABLE ADD COLUMN` / backfill `UPDATE`；连未认证的 `assertion-options` 登录入口也跑。
- 影响：每次 WebAuthn / 轮询请求被固定放大成多次 D1 往返，显著增加延迟与负载。
- 建议：将 schema 修复迁移到部署/迁移阶段，或做进程/DO 级一次性初始化缓存。

---

## Medium

### M1 — Send 访问计数非原子，可越限
- 位置：`src/handlers/sends.rs:124-145`、`src/handlers/sends.rs:687-707`
- 问题：先读快照校验 `access_count >= max_access_count`，再无条件 `UPDATE ... access_count + 1`。
- 影响：并发访问 `maxAccessCount=1` 的 Send 可双双通过，突破访问上限。
- 建议：单条条件更新 `WHERE ... (max_access_count IS NULL OR access_count < max_access_count)` 并检查影响行数。

### M2 — 批量 cipher 操作 N+1
- 位置：`src/handlers/ciphers.rs:326`、`src/handlers/ciphers.rs:347`、`src/handlers/ciphers.rs:367`
- 问题：循环内逐条 `await` 写 D1，`ids` 来自用户且无上限。
- 影响：批量删除/恢复 1000 项 = 1000 次串行往返；中途失败留部分状态。
- 建议：校验 ids 上限，用 `db.batch` 或 `WHERE user_id=? AND id IN (...)` 分块执行。

### M3 — 文件 Send 创建非原子
- 位置：`src/handlers/sends.rs:442-477`
- 问题：`INSERT INTO sends` 与 `INSERT INTO send_files` 分两条，无事务/批处理。
- 影响：第二条失败留下残缺 send（sync 仍返回、上传 URL 404）。
- 建议：两条写入放进同一 D1 batch，或失败时补偿删除。

### M4 — Import 先写后校验，部分导入
- 位置：`src/handlers/import.rs:31-64`
- 问题：先批量写 folders 并提交，之后才逐 cipher 校验 `encrypted_for`；cipher 也按 200 条提前提交。
- 影响：后段校验失败时前段已永久导入，形成部分导入。
- 建议：所有跨记录校验先于任何写入完成，用批次/事务边界保证全成或全不成。

### M5 — sync 静默丢弃坏行 + 敏感信息进日志
- 位置：`src/handlers/sync.rs:53-59`
- 问题：解析失败的 cipher 行被 `filter_map` 静默跳过；`log::warn!("Cannot parse {err:?} {cipher:?}")` 打印整条 cipher 行（含 user_id / folder id / 加密 blob）。
- 影响：客户端看到"成功但缺条目"；敏感记录进生产日志。
- 建议：解析失败直接返回错误或隔离修复；日志只记 cipher id / 错误类型。

### M6 — TOTP 无重放防护
- 位置：`src/core/two_factor.rs:204-216`
- 问题：仅 `totp.check(token, unix_seconds)`，不记录已用 time-step，`skew=1` 放宽窗口。
- 影响：截获的 TOTP 在有效窗口内可重放。
- 建议：记录每用户最近接受的 time-step，拒绝重复或倒退。

### M7 — prelogin 账号枚举
- 位置：`src/handlers/accounts.rs:388-423`
- 问题：对存在用户返回真实 KDF 参数，不存在返回默认 PBKDF2/600000。
- 影响：非默认 KDF 账号可被单请求区分，泄露账号是否存在及其 KDF 配置（与"防枚举"注释矛盾）。
- 建议：评估兼容前提下的枚举缓解，或将该泄露纳入风控/限流。

### M8 — 通知 Durable Object 单实例热点
- 位置：`src/core/notifications.rs:12`、`src/core/notifications.rs:245-249`
- 问题：固定 `id_from_name("global")`，所有用户 WebSocket 落同一 DO 实例。
- 影响：单点热点，违背 DO 分片初衷，限制并发连接规模。
- 建议：按 user/分桶分片 DO 实例。

### M9 — sends 列表无界 + 缺复合索引
- 位置：`src/handlers/sends.rs:202-209`、`sql/schema_full.sql:174`
- 问题：`SELECT * ... ORDER BY updated_at DESC` 无 LIMIT，`continuationToken: null`；仅有 `idx_sends_user_id`，缺 `(user_id, updated_at DESC)`。
- 影响：列表/轮询每次全读 + 排序，随 sends 数量增长。
- 建议：加分页上限与 continuation token，补 `(user_id, updated_at DESC)` 索引。

### M10 — 裸 `/accounts/*` 路由被静态资产层吞掉（死路由）
- 位置：`src/router.rs:41`、`src/router.rs:51` vs `wrangler.jsonc:65`
- 问题：`run_worker_first` 仅列 `/api/*`、`/identity/*`、`/sends/*`、`/notifications/*`、`/demo.html`、`/icons/*`；裸 `/accounts/webauthn/assertion-options`、`/accounts/verify-password` 不在其中。
- 影响：这两条被 SPA fallback 拦截，请求永远到不了 Worker（死路由；带前缀的等价版本仍可用）。
- 建议：删除死路由，或把对应前缀加入 `run_worker_first`。

---

## Low

### L1 — 登录限流静默 fail-open
- 位置：`src/handlers/identity.rs:288-300`
- 问题：双层 `if let Ok(...)`，绑定缺失或限流服务异常时直接放行，无失败计数兜底。
- 建议：限流不可用时记录/告警，并引入服务端失败计数或明确 fail-closed 策略。

### L2 — 业务代码 `expect()` panic（违反 AGENTS.md）
- 位置：`src/core/two_factor.rs:14-20`、`src/handlers/identity.rs:204`、`src/core/webauthn.rs:1130`、`src/handlers/sends.rs:70`
- 问题：RNG 失败用 `expect()`，会 panic 成 500 而非受控 `AppError`。
- 建议：相关函数返回 `Result`，RNG 失败映射 `AppError::Internal`。

### L3 — CORS `Any/Any/Any`
- 位置：`src/lib.rs:26-29`
- 问题：允许任意源 + 任意头。Bearer-token（无 cookie）API 下属 Bitwarden 惯例，影响有限，但任意源可携用户 token 发请求。
- 建议：按需收敛允许源，或确认威胁模型可接受。

### L4 — 100% 日志持久化成本
- 位置：`wrangler.jsonc:48-55`
- 问题：`head_sampling_rate=1` + `persist=true`。
- 影响：高流量下成本/配额压力。
- 建议：生产降低采样率。

### L5 — 分片 hash 质量差 + 死代码
- 位置：`src/entry.js:156-174`
- 问题：`computeRequestShard` 用 `charCodeAt(0)`（首字符）做 hash，分布极差；icons 分支是死代码（`/icons/*` 在 entry.js:182 已被 `proxyIconRequest` 拦截）；匿名 auth-requests 因 pathname 首字符恒为 `/` 全落同一桶。
- 建议：删除 icons 死分支；分桶改用完整哈希（如 FNV/对整串求和）。

### L6 — 重复索引写放大
- 位置：`sql/schema_full.sql:178`
- 问题：`idx_send_file_chunks_send_file_id` 与复合主键 `(send_file_id, chunk_index)` 左前缀重复。
- 建议：删除该二级索引，保留复合主键即可。

### L7 — Rust icons handler 不可达（死代码）
- 位置：`src/handlers/icons.rs`、`src/router.rs:23`
- 问题：`/icons/*` 在 JS 入口已被拦截，`icons::get_icon` 永不执行，与 entry.js 图标代理职责重复。
- 建议：删除 Rust 侧 icons handler 与路由。

### L8 — crypto 模块全 dead_code 且迭代数为 1
- 位置：`src/core/crypto.rs`
- 问题：整文件 `#[allow(dead_code)]`，`hash_master_key` 用 `iterations=1`（crypto.rs:84）。当前似未接入主登录路径。
- 建议：若不使用则删除；若启用必须复核 PBKDF2 迭代数。

---

## 性能影响排序（热路径固定开销）

1. `/api/sync`（H6）：最重读路径，全量无界，开销随 vault 大小线性，轮询/重试翻倍。
2. WebAuthn / auth-requests 每请求 DDL（H8）：登录与轮询入口被固定放大成多次 D1 往返，含未认证入口。
3. `/api/d1/usage`（C1）：全表 `SUM(LENGTH)`，10ms CPU 预算下匿名可触发。
4. Send 文件全量入内存（H7）：大文件 OOM / CPU 超限。
5. 批量 cipher N+1（M2）、sends 列表无索引排序（M9）、通知单 DO 热点（M8）。

## 建议修复顺序

C1 → H1 / H2 / H3 / H4 / H5（认证安全）→ H6 / H8（同步与 schema 热路径）→ H7（文件内存）→ M 级 → L 级。

---

## 审查方法说明

- 入口/路由/并发、认证/2FA/JWT、WebAuthn、数据层、加密/通知/配置 五个子系统分别深审。
- 加密 / 通知 / config / usage / icons 子系统由主审查者逐文件通读核实。
- C1、M8、M10 三个关键点经源码逐行确认。
- 未运行 `worker-build`（按既定约束仅做代码审查）。
