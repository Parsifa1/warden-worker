use axum::{extract::State, http::HeaderMap, Json};
use constant_time_eq::constant_time_eq;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use wasm_bindgen::JsValue;
use worker::{query, Env};

use crate::{
    auth::Claims,
    db,
    error::AppError,
    models::user::{KeyData, PreloginResponse, RegisterRequest, User},
    two_factor, webauthn,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeMasterPasswordRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub user_symmetric_key: String,
    #[serde(default)]
    pub user_asymmetric_keys: Option<KeyData>,
    #[serde(default)]
    pub kdf: Option<i32>,
    #[serde(default)]
    pub kdf_iterations: Option<i32>,
    #[serde(default)]
    pub kdf_memory: Option<i32>,
    #[serde(default)]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub new_email: String,
    pub user_symmetric_key: String,
    #[serde(default)]
    pub kdf: Option<i32>,
    #[serde(default)]
    pub kdf_iterations: Option<i32>,
    #[serde(default)]
    pub kdf_memory: Option<i32>,
    #[serde(default)]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAvatarRequest {
    #[allow(dead_code)]
    pub avatar_color: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileData {
    #[allow(dead_code)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPasswordRequest {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfFlatRequest {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: String,
    #[serde(alias = "NewMasterPasswordHash")]
    pub new_master_password_hash: String,
    #[serde(alias = "Key")]
    pub key: String,
    #[serde(alias = "kdfType", alias = "KdfType")]
    pub kdf: i32,
    #[serde(alias = "KdfIterations", alias = "iterations", alias = "Iterations")]
    pub kdf_iterations: i32,
    #[serde(default)]
    #[serde(alias = "KdfMemory", alias = "memory", alias = "Memory")]
    pub kdf_memory: Option<i32>,
    #[serde(default)]
    #[serde(alias = "KdfParallelism", alias = "parallelism", alias = "Parallelism")]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfParams {
    #[serde(alias = "kdfType", alias = "KdfType")]
    pub kdf: i32,
    #[serde(alias = "KdfIterations", alias = "iterations", alias = "Iterations")]
    pub kdf_iterations: i32,
    #[serde(default)]
    #[serde(alias = "KdfMemory", alias = "memory", alias = "Memory")]
    pub kdf_memory: Option<i32>,
    #[serde(default)]
    #[serde(alias = "KdfParallelism", alias = "parallelism", alias = "Parallelism")]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfData {
    #[serde(alias = "Kdf")]
    pub kdf: ChangeKdfParams,
    #[serde(alias = "Salt")]
    pub salt: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfVwRequest {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: String,
    #[serde(alias = "NewMasterPasswordHash")]
    pub new_master_password_hash: String,
    #[serde(alias = "Key")]
    pub key: String,
    #[serde(alias = "AuthenticationData")]
    pub authentication_data: ChangeKdfData,
    #[serde(alias = "UnlockData")]
    pub unlock_data: ChangeKdfData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfObjectRequest {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: String,
    #[serde(alias = "NewMasterPasswordHash")]
    pub new_master_password_hash: String,
    #[serde(alias = "Key")]
    pub key: String,
    #[serde(alias = "Kdf")]
    pub kdf: ChangeKdfParams,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ChangeKdfPayload {
    Vw(ChangeKdfVwRequest),
    Obj(ChangeKdfObjectRequest),
    Flat(ChangeKdfFlatRequest),
}

#[worker::send]
pub async fn profile(claims: Claims, State(env): State<Arc<Env>>) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let two_factor_enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?
        || webauthn::is_webauthn_enabled(&db, &claims.sub).await?;
    let user: User = query!(&db, "SELECT * FROM users WHERE id = ?1", claims.sub)
        .map_err(|_| AppError::Database)?
        .first(None)
        .await?
        .ok_or(AppError::NotFound("User not found".to_string()))?;

    Ok(Json(json!({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "emailVerified": user.email_verified,
        "premium": true,
        "premiumFromOrganization": false,
        "masterPasswordHint": user.master_password_hint,
        "culture": "en-US",
        "twoFactorEnabled": two_factor_enabled,
        "key": user.key,
        "privateKey": user.private_key,
        "securityStamp": user.security_stamp,
        "avatarColor": user.avatar_color,
        "organizations": [],
        "object": "profile"
    })))
}

#[worker::send]
pub async fn post_profile(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ProfileData>,
) -> Result<Json<Value>, AppError> {
    let name = payload.name.unwrap_or_default();

    if name.len() > 50 {
        return Err(AppError::BadRequest(
            "The field Name must be a string with a maximum length of 50.".to_string(),
        ));
    }

    let db = db::get_db(&env)?;
    let now = crate::utils::time_now();

    db.prepare("UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[name.into(), now.into(), claims.sub.clone().into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    profile(claims, State(env)).await
}

#[worker::send]
pub async fn post_security_stamp(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let now = crate::utils::time_now();
    let security_stamp = Uuid::new_v4().to_string();

    db.prepare("UPDATE users SET security_stamp = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            security_stamp.clone().into(),
            now.into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let two_factor_enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    let user: User = query!(&db, "SELECT * FROM users WHERE id = ?1", claims.sub)
        .map_err(|_| AppError::Database)?
        .first(None)
        .await?
        .ok_or(AppError::NotFound("User not found".to_string()))?;

    Ok(Json(json!({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "emailVerified": user.email_verified,
        "premium": true,
        "premiumFromOrganization": false,
        "masterPasswordHint": user.master_password_hint,
        "culture": "en-US",
        "twoFactorEnabled": two_factor_enabled,
        "key": user.key,
        "privateKey": user.private_key,
        "securityStamp": user.security_stamp,
        "organizations": [],
        "object": "profile"
    })))
}

#[worker::send]
pub async fn revision_date(_claims: Claims) -> Result<Json<i64>, AppError> {
    Ok(Json(chrono::Utc::now().timestamp_millis()))
}

#[worker::send]
pub async fn post_kdf(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ChangeKdfPayload>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    let provided_old_hash = match &payload {
        ChangeKdfPayload::Vw(p) => &p.master_password_hash,
        ChangeKdfPayload::Obj(p) => &p.master_password_hash,
        ChangeKdfPayload::Flat(p) => &p.master_password_hash,
    };

    if !constant_time_eq(
        user.master_password_hash.as_bytes(),
        provided_old_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let (new_master_password_hash, key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism) =
        match &payload {
            ChangeKdfPayload::Vw(p) => {
                if p.authentication_data.kdf != p.unlock_data.kdf {
                    return Err(AppError::BadRequest(
                        "KDF settings must be equal for authentication and unlock".to_string(),
                    ));
                }
                if !user.email.eq_ignore_ascii_case(&p.authentication_data.salt)
                    || !user.email.eq_ignore_ascii_case(&p.unlock_data.salt)
                {
                    return Err(AppError::BadRequest(
                        "Invalid master password salt".to_string(),
                    ));
                }

                (
                    p.new_master_password_hash.clone(),
                    p.key.clone(),
                    p.unlock_data.kdf.kdf,
                    p.unlock_data.kdf.kdf_iterations,
                    p.unlock_data.kdf.kdf_memory,
                    p.unlock_data.kdf.kdf_parallelism,
                )
            }
            ChangeKdfPayload::Obj(p) => (
                p.new_master_password_hash.clone(),
                p.key.clone(),
                p.kdf.kdf,
                p.kdf.kdf_iterations,
                p.kdf.kdf_memory,
                p.kdf.kdf_parallelism,
            ),
            ChangeKdfPayload::Flat(p) => (
                p.new_master_password_hash.clone(),
                p.key.clone(),
                p.kdf,
                p.kdf_iterations,
                p.kdf_memory,
                p.kdf_parallelism,
            ),
        };

    validate_kdf(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)?;
    if new_master_password_hash.is_empty() {
        return Err(AppError::BadRequest(
            "Missing newMasterPasswordHash".to_string(),
        ));
    }
    if key.is_empty() {
        return Err(AppError::BadRequest("Missing key".to_string()));
    }

    let now = crate::utils::time_now();
    let security_stamp = Uuid::new_v4().to_string();

    db.prepare(
        "UPDATE users SET master_password_hash = ?1, key = ?2, kdf_type = ?3, kdf_iterations = ?4, kdf_memory = ?5, kdf_parallelism = ?6, security_stamp = ?7, updated_at = ?8 WHERE id = ?9",
    )
    .bind(&[
        new_master_password_hash.into(),
        key.into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        security_stamp.into(),
        now.into(),
        claims.sub.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn prelogin(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = payload["email"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("Missing email".to_string()))?;

    // Check rate limit using IP address as key to prevent email enumeration attacks
    if let Ok(rate_limiter) = env.rate_limiter("LOGIN_RATE_LIMITER") {
        let ip = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");
        let rate_limit_key = format!("prelogin:{}", ip);
        if let Ok(outcome) = rate_limiter.limit(rate_limit_key).await {
            if !outcome.success {
                return Err(AppError::TooManyRequests(
                    "Too many requests. Please try again later.".to_string(),
                ));
            }
        }
    }

    let db = db::get_db(&env)?;

    let stmt = db.prepare(
        "SELECT kdf_type, kdf_iterations, kdf_memory, kdf_parallelism FROM users WHERE email = ?1",
    );
    let query = stmt.bind(&[email.to_lowercase().into()])?;
    let kdf_row: Option<Value> = query.first(None).await.map_err(|_| AppError::Database)?;
    let kdf = kdf_row
        .as_ref()
        .and_then(|row| row.get("kdf_type"))
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .unwrap_or(0);
    let kdf_iterations = kdf_row
        .as_ref()
        .and_then(|row| row.get("kdf_iterations"))
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .unwrap_or(600_000);
    let kdf_memory = kdf_row
        .as_ref()
        .and_then(|row| row.get("kdf_memory"))
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);
    let kdf_parallelism = kdf_row
        .as_ref()
        .and_then(|row| row.get("kdf_parallelism"))
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);

    Ok(Json(PreloginResponse {
        kdf,
        kdf_iterations,
        kdf_memory,
        kdf_parallelism,
    }))
}

#[worker::send]
pub async fn register(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<Value>, AppError> {
    // Check rate limit using IP address as key to prevent mass registration and email enumeration
    if let Ok(rate_limiter) = env.rate_limiter("LOGIN_RATE_LIMITER") {
        let ip = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");
        let rate_limit_key = format!("register:{}", ip);
        if let Ok(outcome) = rate_limiter.limit(rate_limit_key).await {
            if !outcome.success {
                return Err(AppError::TooManyRequests(
                    "Too many requests. Please try again later.".to_string(),
                ));
            }
        }
    }
    let db = db::get_db(&env)?;
    let normalized_email = payload.email.trim().to_lowercase();
    let user_count: Option<i64> = db
        .prepare("SELECT COUNT(1) AS user_count FROM users")
        .first(Some("user_count"))
        .await
        .map_err(|_| AppError::Database)?;
    let user_count = user_count.unwrap_or(0);
    if user_count == 0 {
        let allowed_emails = env
            .secret("ALLOWED_EMAILS")
            .ok()
            .and_then(|secret| secret.as_ref().as_string())
            .unwrap_or_default();
        if !allowed_emails.trim().is_empty()
            && allowed_emails
                .split(",")
                .map(|email| email.trim().to_lowercase())
                .all(|email| email != normalized_email)
        {
            return Err(AppError::Unauthorized("Not allowed to signup".to_string()));
        }
    }
    let now = crate::utils::time_now();
    validate_kdf(
        payload.kdf,
        payload.kdf_iterations,
        payload.kdf_memory,
        payload.kdf_parallelism,
    )?;

    let user = User {
        id: Uuid::new_v4().to_string(),
        name: payload.name,
        email: normalized_email,
        email_verified: false,
        master_password_hash: payload.master_password_hash,
        master_password_hint: payload.master_password_hint,
        key: payload.user_symmetric_key,
        private_key: payload.user_asymmetric_keys.encrypted_private_key,
        public_key: payload.user_asymmetric_keys.public_key,
        kdf_type: payload.kdf,
        kdf_iterations: payload.kdf_iterations,
        kdf_memory: payload.kdf_memory,
        kdf_parallelism: payload.kdf_parallelism,
        security_stamp: Uuid::new_v4().to_string(),
        avatar_color: None,
        created_at: now.clone(),
        updated_at: now,
    };

    db.prepare(
        "INSERT INTO users (id, name, email, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
    )
    .bind(&[
        user.id.into(),
        to_js_val(user.name),
        user.email.into(),
        user.master_password_hash.into(),
        user.key.into(),
        user.private_key.into(),
        user.public_key.into(),
        user.kdf_type.into(),
        user.kdf_iterations.into(),
        to_js_val(user.kdf_memory),
        to_js_val(user.kdf_parallelism),
        user.security_stamp.into(),
        user.created_at.into(),
        user.updated_at.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn change_master_password(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ChangeMasterPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    if payload.master_password_hash.is_empty() || payload.new_master_password_hash.is_empty() {
        return Err(AppError::BadRequest(
            "Missing masterPasswordHash".to_string(),
        ));
    }
    if payload.user_symmetric_key.is_empty() {
        return Err(AppError::BadRequest("Missing userSymmetricKey".to_string()));
    }

    let db = db::get_db(&env)?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    if !constant_time_eq(
        user.master_password_hash.as_bytes(),
        payload.master_password_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let now = crate::utils::time_now();
    let security_stamp = Uuid::new_v4().to_string();
    let master_password_hint = payload.master_password_hint.clone();
    let private_key = payload
        .user_asymmetric_keys
        .as_ref()
        .map(|k| k.encrypted_private_key.clone())
        .unwrap_or_else(|| user.private_key.clone());
    let public_key = payload
        .user_asymmetric_keys
        .as_ref()
        .map(|k| k.public_key.clone())
        .unwrap_or_else(|| user.public_key.clone());
    let kdf_type = payload.kdf.unwrap_or(user.kdf_type);
    let kdf_iterations = payload.kdf_iterations.unwrap_or(user.kdf_iterations);
    let kdf_memory = payload.kdf_memory.or(user.kdf_memory);
    let kdf_parallelism = payload.kdf_parallelism.or(user.kdf_parallelism);
    validate_kdf(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)?;

    db.prepare(
        "UPDATE users SET master_password_hash = ?1, master_password_hint = ?2, key = ?3, private_key = ?4, public_key = ?5, kdf_type = ?6, kdf_iterations = ?7, kdf_memory = ?8, kdf_parallelism = ?9, security_stamp = ?10, updated_at = ?11 WHERE id = ?12",
    )
    .bind(&[
        payload.new_master_password_hash.into(),
        to_js_val(master_password_hint),
        payload.user_symmetric_key.into(),
        private_key.into(),
        public_key.into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        security_stamp.into(),
        now.into(),
        claims.sub.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn change_email(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ChangeEmailRequest>,
) -> Result<Json<Value>, AppError> {
    if payload.master_password_hash.is_empty() || payload.new_master_password_hash.is_empty() {
        return Err(AppError::BadRequest(
            "Missing masterPasswordHash".to_string(),
        ));
    }
    if payload.new_email.trim().is_empty() {
        return Err(AppError::BadRequest("Missing newEmail".to_string()));
    }
    if payload.user_symmetric_key.is_empty() {
        return Err(AppError::BadRequest("Missing userSymmetricKey".to_string()));
    }

    let new_email = payload.new_email.to_lowercase();

    let db = db::get_db(&env)?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    if !constant_time_eq(
        user.master_password_hash.as_bytes(),
        payload.master_password_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let now = crate::utils::time_now();
    let security_stamp = Uuid::new_v4().to_string();
    let kdf_type = payload.kdf.unwrap_or(user.kdf_type);
    let kdf_iterations = payload.kdf_iterations.unwrap_or(user.kdf_iterations);
    let kdf_memory = payload.kdf_memory.or(user.kdf_memory);
    let kdf_parallelism = payload.kdf_parallelism.or(user.kdf_parallelism);
    validate_kdf(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)?;

    db.prepare(
        "UPDATE users SET email = ?1, email_verified = ?2, master_password_hash = ?3, key = ?4, kdf_type = ?5, kdf_iterations = ?6, kdf_memory = ?7, kdf_parallelism = ?8, security_stamp = ?9, updated_at = ?10 WHERE id = ?11",
    )
    .bind(&[
        new_email.into(),
        false.into(),
        payload.new_master_password_hash.into(),
        payload.user_symmetric_key.into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        security_stamp.into(),
        now.into(),
        claims.sub.into(),
    ])?
    .run()
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::BadRequest("Email already in use".to_string())
        } else {
            AppError::Database
        }
    })?;

    Ok(Json(json!({})))
}

fn to_js_val<T: Into<JsValue>>(val: Option<T>) -> JsValue {
    val.map(Into::into).unwrap_or(JsValue::NULL)
}

fn validate_kdf(
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
) -> Result<(), AppError> {
    const PBKDF2_KDF_TYPE: i32 = 0;
    const ARGON2ID_KDF_TYPE: i32 = 1;
    const PBKDF2_MIN_ITERATIONS: i32 = 600_000;
    const ARGON2ID_MIN_MEMORY_MB: i32 = 15;
    const ARGON2ID_MAX_MEMORY_MB: i32 = 1024;
    const ARGON2ID_MIN_PARALLELISM: i32 = 1;
    const ARGON2ID_MAX_PARALLELISM: i32 = 16;

    if kdf_type != PBKDF2_KDF_TYPE && kdf_type != ARGON2ID_KDF_TYPE {
        return Err(AppError::BadRequest("Unsupported KDF type".to_string()));
    }
    if kdf_type < 0 {
        return Err(AppError::BadRequest("Invalid KDF type".to_string()));
    }
    if kdf_iterations <= 0 {
        return Err(AppError::BadRequest("Invalid KDF iterations".to_string()));
    }

    if kdf_type == PBKDF2_KDF_TYPE {
        if kdf_iterations < PBKDF2_MIN_ITERATIONS {
            return Err(AppError::BadRequest(
                "PBKDF2 requires at least 600000 iterations".to_string(),
            ));
        }
        return Ok(());
    }

    let Some(kdf_memory) = kdf_memory else {
        return Err(AppError::BadRequest(
            "Argon2id requires kdfMemory".to_string(),
        ));
    };
    let Some(kdf_parallelism) = kdf_parallelism else {
        return Err(AppError::BadRequest(
            "Argon2id requires kdfParallelism".to_string(),
        ));
    };

    if !(ARGON2ID_MIN_MEMORY_MB..=ARGON2ID_MAX_MEMORY_MB).contains(&kdf_memory) {
        return Err(AppError::BadRequest(
            "Argon2id kdfMemory must be between 15 and 1024".to_string(),
        ));
    }
    if !(ARGON2ID_MIN_PARALLELISM..=ARGON2ID_MAX_PARALLELISM).contains(&kdf_parallelism) {
        return Err(AppError::BadRequest(
            "Argon2id kdfParallelism must be between 1 and 16".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_kdf, ChangeKdfPayload};
    use serde_json::json;

    #[test]
    fn validate_kdf_pbkdf2_requires_min_iterations() {
        assert!(validate_kdf(0, 599_999, None, None).is_err());
        assert!(validate_kdf(0, 600_000, None, None).is_ok());
    }

    #[test]
    fn validate_kdf_argon2id_requires_memory_and_parallelism() {
        assert!(validate_kdf(1, 3, None, Some(4)).is_err());
        assert!(validate_kdf(1, 3, Some(64), None).is_err());
        assert!(validate_kdf(1, 3, Some(64), Some(4)).is_ok());
    }

    #[test]
    fn validate_kdf_argon2id_enforces_ranges() {
        assert!(validate_kdf(1, 3, Some(14), Some(4)).is_err());
        assert!(validate_kdf(1, 3, Some(1025), Some(4)).is_err());
        assert!(validate_kdf(1, 3, Some(64), Some(0)).is_err());
        assert!(validate_kdf(1, 3, Some(64), Some(17)).is_err());
        assert!(validate_kdf(1, 3, Some(64), Some(4)).is_ok());
    }

    #[test]
    fn validate_kdf_rejects_unsupported_kdf_type() {
        assert!(validate_kdf(2, 1, None, None).is_err());
        assert!(validate_kdf(-1, 1, None, None).is_err());
    }

    #[test]
    fn change_kdf_payload_deserializes_flat_and_object_kdf_shapes() {
        let flat = json!({
            "masterPasswordHash": "old",
            "newMasterPasswordHash": "new",
            "key": "k",
            "kdf": 1,
            "kdfIterations": 3,
            "kdfMemory": 64,
            "kdfParallelism": 4
        });
        let obj = json!({
            "MasterPasswordHash": "old",
            "NewMasterPasswordHash": "new",
            "Key": "k",
            "Kdf": {
                "KdfType": 1,
                "Iterations": 3,
                "Memory": 64,
                "Parallelism": 4
            }
        });

        assert!(serde_json::from_value::<ChangeKdfPayload>(flat).is_ok());
        assert!(serde_json::from_value::<ChangeKdfPayload>(obj).is_ok());
    }
}

#[worker::send]
pub async fn send_verification_email() -> Result<Json<String>, AppError> {
    Ok(Json("fixed-token-to-mock".to_string()))
}

#[worker::send]
pub async fn update_avatar(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<UpdateAvatarRequest>,
) -> Result<Json<Value>, AppError> {
    if let Some(ref color) = payload.avatar_color {
        if color.len() != 7 {
            return Err(AppError::BadRequest(
                "The field AvatarColor must be a HTML/Hex color code with a length of 7 characters"
                    .to_string(),
            ));
        }
    }

    let db = db::get_db(&env)?;
    let now = crate::utils::time_now();

    db.prepare("UPDATE users SET avatar_color = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            to_js_val(payload.avatar_color.clone()),
            now.into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let two_factor_enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?
        || webauthn::is_webauthn_enabled(&db, &claims.sub).await?;
    let user: User = query!(&db, "SELECT * FROM users WHERE id = ?1", claims.sub)
        .map_err(|_| AppError::Database)?
        .first(None)
        .await?
        .ok_or(AppError::NotFound("User not found".to_string()))?;

    Ok(Json(json!({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "emailVerified": user.email_verified,
        "premium": true,
        "premiumFromOrganization": false,
        "masterPasswordHint": user.master_password_hint,
        "culture": "en-US",
        "twoFactorEnabled": two_factor_enabled,
        "key": user.key,
        "privateKey": user.private_key,
        "securityStamp": user.security_stamp,
        "avatarColor": user.avatar_color,
        "organizations": [],
        "object": "profile"
    })))
}

#[worker::send]
pub async fn verify_password(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<VerifyPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    if payload.master_password_hash.is_empty() {
        return Err(AppError::BadRequest(
            "Missing masterPasswordHash".to_string(),
        ));
    }

    let db = db::get_db(&env)?;
    let stored_hash: Option<String> = db
        .prepare("SELECT master_password_hash FROM users WHERE id = ?1")
        .bind(&[claims.sub.into()])?
        .first(Some("master_password_hash"))
        .await
        .map_err(|_| AppError::Database)?;
    let Some(stored_hash) = stored_hash else {
        return Err(AppError::NotFound("User not found".to_string()));
    };

    if !constant_time_eq(
        stored_hash.as_bytes(),
        payload.master_password_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    Ok(Json(Value::Null))
}
