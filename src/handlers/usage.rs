use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::{auth::Claims, db, error::AppError};

const D1_MAX_BYTES: i64 = 500 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageQuery {
    #[allow(dead_code)]
    user_id: Option<String>,
}

async fn sum_i64(
    db: &worker::D1Database,
    sql: &str,
    binds: &[worker::wasm_bindgen::JsValue],
) -> Result<i64, AppError> {
    let bytes: Option<i64> = db
        .prepare(sql)
        .bind(binds)?
        .first(Some("bytes"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(bytes.unwrap_or(0))
}

#[worker::send]
pub async fn d1_usage(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Query(_q): Query<UsageQuery>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let uid = &claims.sub;

    let ciphers_bytes = sum_i64(
        &db,
        "SELECT COALESCE(SUM(LENGTH(data)), 0) AS bytes FROM ciphers WHERE user_id = ?1",
        &[uid.into()],
    )
    .await?;
    let sends_text_bytes = sum_i64(
        &db,
        "SELECT COALESCE(SUM(LENGTH(data)), 0) AS bytes FROM sends WHERE type = 0 AND user_id = ?1",
        &[uid.into()],
    )
    .await?;
    let sends_file_meta_bytes = sum_i64(
        &db,
        "SELECT COALESCE(SUM(LENGTH(data)), 0) AS bytes FROM sends WHERE type = 1 AND user_id = ?1",
        &[uid.into()],
    )
    .await?;

    let send_files_inline_bytes = sum_i64(
        &db,
        "SELECT COALESCE(SUM(LENGTH(data_base64)), 0) AS bytes FROM send_files WHERE user_id = ?1",
        &[uid.into()],
    )
    .await?;
    let send_files_chunks_bytes = sum_i64(
        &db,
        "SELECT COALESCE(SUM(LENGTH(c.data_base64)), 0) AS bytes FROM send_file_chunks c JOIN send_files sf ON sf.id = c.send_file_id WHERE sf.user_id = ?1",
        &[uid.into()],
    )
    .await?;

    let folders_bytes = sum_i64(
        &db,
        "SELECT COALESCE(SUM(LENGTH(name)), 0) AS bytes FROM folders WHERE user_id = ?1",
        &[uid.into()],
    )
    .await?;
    let devices_bytes = sum_i64(
        &db,
        "SELECT COALESCE(SUM(LENGTH(device_identifier) + LENGTH(COALESCE(device_name, '')) + LENGTH(COALESCE(remember_token_hash, ''))), 0) AS bytes FROM devices WHERE user_id = ?1",
        &[uid.into()],
    )
    .await?;
    let totp_bytes = sum_i64(
        &db,
        "SELECT COALESCE(SUM(LENGTH(secret_enc)), 0) AS bytes FROM two_factor_authenticator WHERE user_id = ?1",
        &[uid.into()],
    )
    .await?;
    let users_bytes = sum_i64(
        &db,
        "SELECT COALESCE(SUM(LENGTH(email) + LENGTH(COALESCE(name, '')) + LENGTH(master_password_hash) + LENGTH(COALESCE(master_password_hint, '')) + LENGTH(key) + LENGTH(private_key) + LENGTH(public_key)), 0) AS bytes FROM users WHERE id = ?1",
        &[uid.into()],
    )
    .await?;

    let send_files_bytes = send_files_inline_bytes + send_files_chunks_bytes;

    let mut items = vec![
        json!({"label": "Ciphers", "bytes": ciphers_bytes}),
        json!({"label": "Sends (text)", "bytes": sends_text_bytes}),
        json!({"label": "Sends (file metadata)", "bytes": sends_file_meta_bytes}),
        json!({"label": "Send files", "bytes": send_files_bytes}),
        json!({"label": "Folders", "bytes": folders_bytes}),
        json!({"label": "Devices", "bytes": devices_bytes}),
        json!({"label": "TOTP", "bytes": totp_bytes}),
        json!({"label": "Users", "bytes": users_bytes}),
    ];
    items.sort_by(|a, b| {
        b.get("bytes")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .cmp(&a.get("bytes").and_then(|v| v.as_i64()).unwrap_or(0))
    });

    let total_bytes: i64 = items
        .iter()
        .map(|v| v.get("bytes").and_then(|v| v.as_i64()).unwrap_or(0))
        .sum();
    let total_percent = if D1_MAX_BYTES <= 0 {
        0.0
    } else {
        (total_bytes as f64) * 100.0 / (D1_MAX_BYTES as f64)
    };

    Ok(Json(json!({
        "totalBytes": total_bytes,
        "totalPercent": total_percent,
        "maxBytes": D1_MAX_BYTES,
        "items": items
    })))
}
