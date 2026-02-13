use axum::{extract::State, http::HeaderMap, Json};
use constant_time_eq::constant_time_eq;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::{auth::Claims, db, error::AppError, webauthn};

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SecretVerificationData {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
}

impl SecretVerificationData {
    async fn validate(&self, db: &worker::D1Database, user_id: &str) -> Result<(), AppError> {
        match (&self.master_password_hash, &self.otp) {
            (Some(master_password_hash), None) => {
                let stored_hash: Option<String> = db
                    .prepare("SELECT master_password_hash FROM users WHERE id = ?1")
                    .bind(&[user_id.into()])?
                    .first(Some("master_password_hash"))
                    .await
                    .map_err(|_| AppError::Database)?;
                let Some(stored_hash) = stored_hash else {
                    return Err(AppError::NotFound("User not found".to_string()));
                };
                if !constant_time_eq(stored_hash.as_bytes(), master_password_hash.as_bytes()) {
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }
                Ok(())
            }
            (None, Some(_)) => Err(AppError::BadRequest(
                "OTP validation is not supported".to_string(),
            )),
            _ => Err(AppError::BadRequest("No validation provided".to_string())),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTwoFactorWebAuthnRequest {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
    id: i32,
    name: Option<String>,
    #[serde(rename = "deviceResponse")]
    device_response: WebAuthnDeviceResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTwoFactorWebAuthnDeleteRequest {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
    id: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnDeviceResponse {
    response: WebAuthnDeviceResponseInner,
}

#[derive(Debug, Deserialize)]
struct WebAuthnDeviceResponseInner {
    #[serde(rename = "AttestationObject", alias = "attestationObject")]
    attestation_object: String,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    client_data_json: String,
}

async fn webauthn_response(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<serde_json::Value, AppError> {
    let keys = webauthn::list_webauthn_keys(db, user_id).await?;
    let key_items: Vec<Value> = keys
        .into_iter()
        .map(|k| {
            json!({
                "Name": k.name,
                "Id": k.id,
                "Migrated": k.migrated
            })
        })
        .collect();
    Ok(json!({
        "Enabled": !key_items.is_empty(),
        "Keys": key_items
    }))
}

#[worker::send]
pub async fn get_webauthn(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    payload.validate(&db, &claims.sub).await?;
    Ok(Json(webauthn_response(&db, &claims.sub).await?))
}

#[worker::send]
pub async fn get_webauthn_challenge(
    claims: Claims,
    headers: HeaderMap,
    State(env): State<Arc<Env>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    payload.validate(&db, &claims.sub).await?;

    let user_row: Value = db
        .prepare("SELECT name, email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let user_name = user_row.get("name").and_then(|v| v.as_str());
    let user_email = user_row
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?;

    let rp_id = webauthn::rp_id_from_headers(&headers);
    let origin = webauthn::origin_from_headers(&headers);
    let challenge = webauthn::issue_registration_challenge(
        &db,
        &claims.sub,
        user_name,
        user_email,
        &rp_id,
        &origin,
    )
    .await?;

    Ok(Json(challenge))
}

#[worker::send]
pub async fn put_webauthn(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<UpdateTwoFactorWebAuthnRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    SecretVerificationData {
        master_password_hash: payload.master_password_hash.clone(),
        otp: payload.otp.clone(),
    }
    .validate(&db, &claims.sub)
    .await?;

    webauthn::register_webauthn_credential(
        &db,
        &claims.sub,
        payload.id,
        payload.name.as_deref().unwrap_or(""),
        &payload.device_response.response.attestation_object,
        &payload.device_response.response.client_data_json,
    )
    .await?;

    Ok(Json(webauthn_response(&db, &claims.sub).await?))
}

#[worker::send]
pub async fn delete_webauthn(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<UpdateTwoFactorWebAuthnDeleteRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    SecretVerificationData {
        master_password_hash: payload.master_password_hash.clone(),
        otp: payload.otp.clone(),
    }
    .validate(&db, &claims.sub)
    .await?;

    webauthn::delete_webauthn_key(&db, &claims.sub, payload.id).await?;
    Ok(Json(webauthn_response(&db, &claims.sub).await?))
}
