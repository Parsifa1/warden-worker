use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::{
    auth::Claims,
    db,
    error::AppError,
    models::{
        cipher::{Cipher, CipherDBModel},
        folder::{Folder, FolderResponse},
        send::{send_to_json, SendDBModel},
        sync::Profile,
        user::User,
    },
    two_factor,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncQuery {
    pub last_sync_date: Option<String>,
}

#[worker::send]
pub async fn get_sync_data(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Query(q): Query<SyncQuery>,
) -> Result<Json<Value>, AppError> {
    let user_id = claims.sub;
    let db = db::get_db(&env)?;
    let since = q.last_sync_date.as_deref();

    // Fetch profile
    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let folders_db: Vec<Folder> = if let Some(since) = since {
        db.prepare("SELECT * FROM folders WHERE user_id = ?1 AND updated_at > ?2")
            .bind(&[user_id.clone().into(), since.into()])?
            .all()
            .await?
            .results()?
    } else {
        db.prepare("SELECT * FROM folders WHERE user_id = ?1")
            .bind(&[user_id.clone().into()])?
            .all()
            .await?
            .results()?
    };

    let folders: Vec<FolderResponse> = folders_db.into_iter().map(|f| f.into()).collect();

    let ciphers: Vec<Value> = if let Some(since) = since {
        db.prepare("SELECT * FROM ciphers WHERE user_id = ?1 AND updated_at > ?2")
            .bind(&[user_id.clone().into(), since.into()])?
            .all()
            .await?
            .results()?
    } else {
        db.prepare("SELECT * FROM ciphers WHERE user_id = ?1")
            .bind(&[user_id.clone().into()])?
            .all()
            .await?
            .results()?
    };

    let ciphers = ciphers
        .into_iter()
        .filter_map(
            |cipher| match serde_json::from_value::<CipherDBModel>(cipher.clone()) {
                Ok(cipher) => Some(cipher),
                Err(err) => {
                    log::warn!("Cannot parse {err:?} {cipher:?}");
                    None
                }
            },
        )
        .map(|cipher| cipher.into())
        .collect::<Vec<Cipher>>();

    let send_rows: Vec<Value> = if let Some(since) = since {
        db.prepare(
            "SELECT * FROM sends WHERE user_id = ?1 AND updated_at > ?2 ORDER BY updated_at DESC",
        )
        .bind(&[user_id.clone().into(), since.into()])?
        .all()
        .await?
        .results()?
    } else {
        db.prepare("SELECT * FROM sends WHERE user_id = ?1 ORDER BY updated_at DESC")
            .bind(&[user_id.clone().into()])?
            .all()
            .await?
            .results()?
    };
    let sends = send_rows
        .into_iter()
        .filter_map(|v| serde_json::from_value::<SendDBModel>(v).ok())
        .map(|s| send_to_json(&s))
        .collect::<Vec<_>>();

    let time = chrono::DateTime::parse_from_rfc3339(&user.created_at)
        .map_err(|_| AppError::Internal)?
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let profile = Profile {
        id: user.id,
        name: user.name,
        email: user.email.clone(),
        master_password_hint: user.master_password_hint,
        security_stamp: user.security_stamp,
        object: "profile".to_string(),
        premium: true,
        premium_from_organization: false,
        email_verified: user.email_verified,
        force_password_reset: false,
        two_factor_enabled: two_factor::is_two_factor_enabled(&db, &user_id).await?,
        uses_key_connector: false,
        creation_date: time,
        key: user.key.clone(),
        private_key: user.private_key,
        avatar_color: user.avatar_color,
    };
    let master_password_unlock = if !user.master_password_hash.is_empty() {
        json!({
            "kdf": {
                "kdfType": user.kdf_type,
                "iterations": user.kdf_iterations,
                "memory": user.kdf_memory,
                "parallelism": user.kdf_parallelism
            },
            "masterKeyEncryptedUserKey": user.key,
            "masterKeyWrappedUserKey": user.key,
            "salt": user.email
        })
    } else {
        Value::Null
    };

    let keys = crate::webauthn::list_webauthn_api_items(&db, &user_id).await?;
    let web_authn_prf_options = keys
        .into_iter()
        .map(|k| {
            json!({
                "credentialId": k.credential_id_b64url,
                "transports": [],
                "encryptedPrivateKey": k.encrypted_private_key,
                "encryptedUserKey": k.encrypted_user_key,
            })
        })
        .collect::<Vec<_>>();
    let response = json!({
        "profile": profile,
        "folders": folders,
        "ciphers": ciphers,
        "sends": sends,
        "domains": serde_json::Value::Null,
        "object": "sync".to_string(),
        "collections": [],
        "policies": [],
        "userDecryption": {
            "masterPasswordUnlock": master_password_unlock,
            "webAuthnPrfOptions": web_authn_prf_options
        }
    });

    Ok(Json(response))
}
