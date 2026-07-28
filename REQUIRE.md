# Warden vs 官方 Bitwarden Server API 差异清单

对比 warden（自建 Bitwarden 兼容服务端, Rust + Cloudflare Workers）与官方 `bitwarden/server`（C#，main 分支）的 API，按重要性排序列出重大差异。

- **P0** — 破坏客户端核心流程（登录/同步/加解密/2FA）
- **P1** — 影响功能完整性
- **P2** — 边缘/兼容性

每条含双方文件位置与影响。`[INFERENCE]` 标记未直读源码的推断。

---

## 🔴 P0 — 破坏客户端核心流程

### 认证与身份

1. **register/finish 不支持 V2 客户端 + 跳过邮箱验证** — `src/handlers/accounts.rs:432-528` vs `src/Identity/Controllers/AccountsController.cs:97-141` + `src/Core/Auth/Models/Api/Request/Accounts/RegisterFinishRequestModel.cs:21-39`。V2 客户端发 `AccountKeys`/`MasterPasswordAuthentication`/`MasterPasswordUnlock` 时因 `user_symmetric_key` 必填反序列化失败；任何人可不经验证邮箱直接注册。

2. **JWT 无 security_stamp，旧 refresh token 永不失效** — `src/handlers/identity.rs:753-792` + `src/core/auth.rs:12-25` vs `src/Identity/IdentityServer/RequestValidators/BaseRequestValidator.cs:623-627`。改密/改邮箱/KDF 切换后旧 token 仍可换发，等同会话固定漏洞。

3. **auth-request 登录绕过 2FA** — `src/handlers/identity.rs:368-470`（注释明写 "bypasses 2FA"）vs `src/Identity/IdentityServer/RequestValidators/BaseRequestValidator.cs:139-185`。受信设备流程可绕过二步验证。

4. **WebAuthn passwordless 登录绕过 2FA** — `src/handlers/identity.rs:639-752` vs `src/Identity/IdentityServer/RequestValidators/WebAuthnGrantValidator.cs:75-78`。启用 2FA 的账号可用 passkey 绕过。

5. **改邮箱不要求 Token** — `src/handlers/accounts.rs:605-677` + `src/handlers/accounts.rs:37-52` vs `src/Api/Auth/Controllers/AccountsController.cs:96-130` + `src/Api/Auth/Models/Request/Accounts/EmailRequestModel.cs:23`。任意已登录用户可把邮箱改成未验证地址，劫持密码重置流程。

6. **改密/改邮箱用 PUT，官方用 POST** — `src/router.rs:119-123` vs `src/Api/Auth/Controllers/AccountsController.cs:147,73`。客户端发 POST → 405，功能完全不可用。

7. **token 响应硬编码 `email_verified:true`** — `src/handlers/identity.rs:83-93` vs `src/Identity/IdentityServer/ProfileService`。注册时 `email_verified=false`（`accounts.rs:487`），但 token 始终声明已验证。

8. **prelogin 响应缺 `kdfSettings`/`salt`，且枚举可区分** — `src/handlers/accounts.rs:367-429` vs `src/Identity/Controllers/AccountsController.cs:184-209`。未注册邮箱返回固定默认值，与已注册用户（常 Argon2id）可区分；新客户端读 `KdfSettings` 拿不到。

### Sync 与加密

9. **`object: "default_object"` 而非 `"cipher"`** — `src/models/cipher.rs:186` vs `src/Api/Vault/Models/Response/CipherResponseModel.cs:36`。所有走 DB 反序列化的响应（`/api/sync`、`PUT /delete`、`PUT /restore`）返回错误 object 值，客户端按 object 分发反序列化器 → cipher 被丢弃或 sync 整体失败。**单点破坏同步。**

10. **cipher 不校验 `encryptedFor`** — `src/models/cipher.rs:349-377` + `src/handlers/ciphers.rs:124-141` vs `src/Api/Vault/Controllers/CiphersController.cs:189-196,221-228,248-260`。绕过 "cipher 必须为 owner 加密" 约束，跨用户/旧密文可静默写入。

11. **`lastKnownRevisionDate` 解析后丢弃，无乐观锁** — `src/models/cipher.rs:376` + `src/handlers/ciphers.rs:144-217` vs `src/Api/Vault/Controllers/CiphersController.cs:260`。并发编辑静默覆盖，密文回滚风险。

12. **无 `collection_ciphers` 表，collectionIds 不持久化** — `src/handlers/ciphers.rs:88-103` + `sql/schema_full.sql:38-60` vs `src/Api/Vault/Controllers/CiphersController.cs:228,255-257`。组织保险箱的 cipher-collection 分配完全不存库，`/api/sync` 永远拿不到。

13. **sync `Profile` 硬编码 `premium:true`/`email_verified:true`/`force_password_reset:false`** — `src/handlers/sync.rs:90-99` vs `src/Api/Models/Response/ProfileResponseModel.cs:43-79`。绕过强制密码重置与邮箱验证。

14. **`two_factor_enabled` 只查 authenticator** — `src/handlers/sync.rs:94` vs `src/Api/Vault/Controllers/SyncController.cs:97`。仅启用 WebAuthn/Email 2FA 的用户被报 `twoFactorEnabled:false`，客户端不要求 2FA → 安全降级。

15. **sync 缺 `domains`（equivalent domains）** — `src/handlers/sync.rs:23-24` vs `src/Api/Vault/Controllers/SyncController.cs:83`。不接受 `excludeDomains` 参数，domains 恒 null，URI 自动填充匹配规则失效。

16. **sync 不过滤不支持的 cipher 类型** — `src/handlers/sync.rs:54-66` vs `src/Api/Vault/Controllers/SyncController.cs:117-142`。老客户端收到 SSHKey/BankAccount 等未知类型可能崩溃。

### TwoFactor / WebAuthn

17. **`GET /two-factor` 响应 schema 完全不兼容** — `src/handlers/two_factor.rs:106-125` vs `src/Api/Auth/Controllers/TwoFactorController.cs:71-81`。warden 返回 `{enabled, providers:[int]}`，官方返回 `{object:"list", data:[{enabled, type, object:"twoFactorProvider"}]}`。客户端无法显示已启用 2FA 列表。

18. **`get-authenticator` 响应缺 `userVerificationToken`** — `src/handlers/two_factor.rs:206-211` vs `src/Api/Auth/Controllers/TwoFactorController.cs:97-107`。后续 enable/disable authenticator 流程被阻塞。

19. **disable 系列响应字段名 `keys` 而非 `type`** — `src/handlers/two_factor.rs:313-317,411-415` vs `src/Api/Auth/Models/Response/TwoFactor/TwoFactorProviderResponseModel.cs`。客户端无法识别 provider 类型。

20. **`POST /webauthn` 响应 `{success:true}` 而非 credential 对象** — `src/handlers/webauthn.rs:322-378` vs `src/Api/Auth/Controllers/WebAuthnController.cs:99-115`。客户端拿不到新 credential，无法更新 passkey 列表。

21. **`POST /webauthn/{id}/delete` 用 `Path<i32>` 而非 `Guid`** — `src/handlers/webauthn.rs:442-452` + `src/router.rs:152-155` vs `src/Api/Auth/Controllers/WebAuthnController.cs:139-150`。客户端发 GUID 字符串 → 400/422，删除 passkey 流程中断。

22. **WebAuthn 注册/更新忽略 `token` 字段** — `src/handlers/webauthn.rs:83-99,69-114` vs `src/Api/Auth/Controllers/WebAuthnController.cs:117-119`。官方用 data-protected token 防重放，warden 仅靠 DB pending challenge，跨会话重放风险。

### Devices / AuthRequests

23. **`GET /api/devices` 列表缺 `lastActivityDate`/`encryptedPublicKey`/`encryptedUserKey`，`isTrusted` 恒 false** — `src/handlers/devices.rs:251-281` vs `src/Core/Auth/Models/Api/Response/DeviceAuthRequestResponseModel.cs:30-50`。受信设备 SSO 与设备密钥迁移不可用。

24. **`POST /api/auth-requests/admin-request` 路由到匿名 handler** — `src/router.rs:83-94` + `src/handlers/devices.rs:511-604` vs `src/Api/Auth/Controllers/AuthRequestsController.cs:73-86`。官方要求 `[Authorize(Application)]` + `Type==AdminApproval`；warden 允许任何人匿名伪造 admin 审批请求。

25. **auth-request 审批不校验 device_identifier 存在性，不设 `ResponseDeviceId`** — `src/handlers/devices.rs:680-735` vs `src/Core/Auth/Services/Implementations/AuthRequestService.cs:178-208`。审批端可用不存在的 device 通过审批。

26. **`GET /api/auth-requests` 仅返回 pending** — `src/handlers/devices.rs:840-847` vs `src/Api/Auth/Controllers/AuthRequestsController.cs:23-32`。客户端登录审批历史页空。

27. **auth-request 过期统一 15min，admin 请求被过早删除** — `src/handlers/devices.rs:94-106` vs `src/Core/Auth/Services/Implementations/AuthRequestService.cs:228-261`。官方 admin 用 7 天窗口；warden 15 分钟内删除，管理员来不及审批。

28. **`get_auth_request_response` 校验 IP + device_type 一致** — `src/handlers/devices.rs:806-832` vs `src/Core/Auth/Services/Implementations/AuthRequestService.cs:43-56`。VPN/移动网络切换 IP 时发起端永远拿不到响应，无密码登录卡死。

### Sends

29. **完全缺失 `PUT /sends/{id}`** — `src/router.rs:178-197` vs `src/Api/Tools/Controllers/SendsController.cs:458-476`。编辑 Send 功能完全不可用。

30. **缺失 `PUT /sends/{id}/remove-password` 与 `remove-auth`** — `src/router.rs:178-197` vs `src/Api/Tools/Controllers/SendsController.cs:478-501`。已加密码的 Send 无法去除密码。

31. **缺失已认证的 `/api/sends/access` 与 `/api/sends/access/file/{fileId}`** — `src/router.rs:178-197` vs `src/Api/Tools/Controllers/SendsController.cs:175-260`。已登录用户（持 `send-access` token）打开 Send 整条链断裂。

32. **Send 密码错误无 2 秒延迟** — `src/handlers/sends.rs:181-196` vs `src/Api/Tools/Controllers/SendsController.cs:95-98`。缺时序攻击缓解，可枚举 Send 状态。

---

## 🟡 P1 — 影响功能完整性

33. **`send-verification-email` 是 stub** — `src/handlers/accounts.rs:802-805` 返回固定 `"fixed-token-to-mock"`，不发邮件、不读 body。注册邮件验证完全不可用。

34. **`verify-password` 返回 null，丢失主密码策略** — `src/handlers/accounts.rs:862-893` vs `src/Api/Auth/Controllers/AccountsController.cs:263-281`。组织用户改密时拿不到策略约束。

35. **`revision-date` 返回当前时间而非账号修订时间** — `src/handlers/accounts.rs:256-259`。客户端每次轮询触发冗余全量 sync。

36. **`post_kdf`/`change_master_password` 只支持 V1 字段** — `src/handlers/accounts.rs:261-365,530-603`。V2 客户端无法切换 KDF / 改主密码。

37. **profile 响应缺 `AccountKeys`/`ForcePasswordReset`/`VerifyDevices`/`Providers` 等** — `src/handlers/accounts.rs:156-184` vs `src/Api/Models/Response/ProfileResponseModel.cs:30-58`。

38. **token 响应 `MasterPasswordUnlock` 多 `MasterKeyWrappedUserKey`，`Salt` 用 email 而非 masterPasswordSalt** — `src/handlers/identity.rs:114-140` vs `src/Core/KeyManagement/Models/Api/Response/MasterPasswordUnlockResponseModel.cs:5-19`。跨服务端迁移后派生主密钥失败。

39. **2FA 仅支持 Authenticator/WebAuthn，缺 YubiKey/Duo/Email/Recover** — `src/router.rs:124-177` vs `src/Api/Auth/Controllers/TwoFactorController.cs:178-296`。

40. **2FA 验证不支持 OTP / AuthRequestAccessCode** — `src/handlers/webauthn.rs:16-46` + `src/handlers/two_factor.rs:27-59` vs `src/Api/Auth/Models/Request/Accounts/SecretVerificationRequestModel.cs`。auth-request 登录设备无法做 2FA 验证。

41. **WebAuthn 多响应缺 `object` 字段，`webauthn_response` 用 PascalCase** — `src/handlers/webauthn.rs:132-136,282-286,315-319` vs 官方对应 ResponseModel。客户端反序列化失败。

42. **`GET /webauthn` 不强制认证** — `src/handlers/webauthn.rs:225-238` vs `src/Api/Auth/Controllers/WebAuthnController.cs:39-47`。未认证返回 200 空列表，应 401。

43. **cipher 响应缺 `attachments`/`key`/`data`/`archivedDate`** — `src/models/cipher.rs:195-287` vs `src/Api/Vault/Models/Response/CipherResponseModel.cs:46-140`。新客户端按 `data` 读 cipher 内容拿到 null；附件完全不可见。

44. **cipher 序列化只覆盖 4 种类型，缺 SSHKey/BankAccount 等** — `src/models/cipher.rs:261-266` vs `src/Api/Vault/Models/Response/CipherResponseModel.cs:60-104`。

45. **大量 cipher 端点缺失** — `src/router.rs:201-220` vs `src/Api/Vault/Controllers/CiphersController.cs:71-1503`。缺 `GET /ciphers`、`PUT /partial`、`PUT /share`、`PUT /collections`、`POST /purge`、全部 attachment、`PUT /archive`/`unarchive`、`PUT /move`。附件/分享/集合分配/归档/清空保险箱全 404。

46. **import 无数量上限** — `src/handlers/import.rs:18-106` vs `src/Api/Tools/Controllers/ImportCiphersController.cs:50-56`（7000/2000 限制）。大导入可打爆 D1。

47. **缺 `POST /ciphers/import-organization`** — `src/router.rs:206` vs `src/Api/Tools/Controllers/ImportCiphersController.cs:69-105`。组织级导入不可用。

48. **folders 缺 `GET`/`GET/{id}`/`DELETE /all`/deprecated 别名** — `src/router.rs:222-224` vs `src/Api/Vault/Controllers/FoldersController.cs:22-117`。

49. **Sends 缺日期校验、501MB 上限、premium 校验** — `src/handlers/sends.rs:286-457` vs `src/Api/Tools/Models/Request/SendRequestModel.cs:228-282`。接受过去日期/超 31 天/过期晚于删除的 Send。

50. **devices 缺 CRUD（POST/PUT/DELETE/GET by Guid）+ 全部信任流端点** — `src/router.rs:57-78` vs `src/Api/Controllers/DevicesController.cs:62-256`。设备重命名/停用/信任管理不可用。

51. **sync 缺 `settings/domains` 端点 + `policiesNew`/`organizations`/`providers`/`accountKeys`/`verifyDevices`** — `src/handlers/sync.rs:134` + `src/models/sync.rs:3-32` vs `src/Api/Controllers/SettingsController.cs:16-44` + `src/Api/Vault/Models/Response/SyncResponseModel.cs:30-78`。

52. **icons 反代 `vault.bitwarden.com`** — `src/handlers/icons.rs:12-53` vs `src/Icons/Controllers/IconsController.cs:55-117`。隐私泄露 + 上游不可达时图标全失效。

53. **config 缺 `suppressOnboardingInterstitials`/`communication`/`fillAssistRules`，featureStates 仅 2 项** — `src/handlers/config.rs:29-62` vs `src/Api/Models/Response/ConfigResponseModel.cs:39-63`。

---

## 🟢 P2 — 边缘/兼容性

54. **token 不支持 `authorization_code`/`client_credentials`/`sso_token` grant type** — `src/handlers/identity.rs:36-66`。CLI api-key 登录、OAuth、SSO 不可用。

55. **大量辅助端点缺失** — `/accounts/password-hint`、`/email-token`、`/verify-email*`、`/set-password`、`/keys`、`/organizations`、`/avatar`、`DELETE /accounts`、`/security-stamp` 等。`post_security_stamp`/`update_avatar`/`post_profile` 函数已写但未挂路由（死代码）。

56. **auth request 无 `authentication_date`，可重放** — `src/handlers/devices.rs:54-84,640-771` vs `src/Core/Auth/Entities/AuthRequest.cs:52-66`。已消费的请求 15 分钟内可重复用于登录。

57. **`origin` 返回完整 URL 而非 host** — `src/handlers/devices.rs:142-156`。客户端反 phishing 比对失配。

58. **device_type 缺 26=DuckDuckGo，24 大小写不符** — `src/handlers/devices.rs:164-193` vs `src/Core/Enums/DeviceType.cs`。

59. **Sends `id` 返回原始 UUID 而非 base64url** — `src/models/send.rs:235` vs `src/Api/Tools/Models/Response/SendAccessResponseModel.cs:42`。

60. **Send `password` 重编码为 URL_SAFE_NO_PAD** — `src/models/send.rs:212-216`。哈希比对失配。

61. **cipher `collectionIds` 省略而非 `[]`** — `src/models/cipher.rs:155-156` vs `src/Api/Vault/Models/Response/CipherDetailsResponseModel.cs:177-188`。

62. **`reprompt` 用裸 `i32` 不校验枚举** — `src/models/cipher.rs:374`。

63. **folders/sends 删除返回 200+`{}` 而非 204 void** — `src/handlers/folders.rs:55-73`、`src/handlers/sends.rs:659`。

64. **config `server.name` 硬编码 "Vaultwarden"，`version` 硬编码 "2025.12.0"** — `src/handlers/config.rs:37-40,76-78`。

65. **`/api/d1/usage` 为 warden 自有端点** — 非破坏，仅自有。

---

## 建议优先修复顺序

### 第一波（单点修复即恢复核心流程）

- **#9** `object: "default_object"` → `"cipher"`（一行改动，恢复 sync）
- **#6** 改密/改邮箱 PUT → POST（路由方法改）
- **#17** `GET /two-factor` 响应 schema（重写序列化）
- **#29** 缺失 `PUT /sends/{id}`（补路由+handler）
- **#14** `two_factor_enabled` 查全 provider（扩展 `is_authenticator_enabled`）

### 第二波（安全漏洞）

- **#2** JWT 加 security_stamp
- **#3 #4** auth-request/WebAuthn 登录补 2FA
- **#5** 改邮箱要求 Token
- **#24** admin-request 加鉴权
- **#1** register 支持 V2 + 邮箱验证

### 第三波（schema 补全）

- **#43** cipher 响应补 `attachments`/`key`/`data`
- **#45** 补 cipher 缺失端点（attachment/share/archive）
- **#13** sync Profile 读真实字段
- **#51** 补 sync `domains`/`policiesNew`/组织字段
