use axum::{extract::State, Json};
use chrono::Utc;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, Env};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::models::cipher::{
    Cipher, CipherData, CipherRequestData, CipherRequestFlat, CreateCipherRequest,
};
use axum::extract::Path;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CipherIdsRequest {
    ids: Vec<String>,
}

async fn get_cipher_dbmodel(
    env: &Arc<Env>,
    cipher_id: &str,
    user_id: &str,
) -> Result<crate::models::cipher::CipherDBModel, AppError> {
    let db = db::get_db(env)?;
    query!(
        &db,
        "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
        cipher_id,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Cipher not found".to_string()))
}

async fn create_cipher_inner(
    claims: Claims,
    env: &Arc<Env>,
    cipher_data_req: CipherRequestData,
    collection_ids: Vec<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let cipher_data = CipherData {
        name: cipher_data_req.name,
        notes: cipher_data_req.notes,
        login: cipher_data_req.login,
        card: cipher_data_req.card,
        identity: cipher_data_req.identity,
        secure_note: cipher_data_req.secure_note,
        fields: cipher_data_req.fields,
        password_history: cipher_data_req.password_history,
        reprompt: cipher_data_req.reprompt,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite,
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: None,
        created_at: now.clone(),
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: if collection_ids.is_empty() {
            None
        } else {
            Some(collection_ids)
        },
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
         cipher.id,
         cipher.user_id,
         cipher.organization_id,
         cipher.r#type,
         data,
         cipher.favorite,
         cipher.folder_id,
         cipher.created_at,
         cipher.updated_at,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    Ok(Json(cipher))
}

fn parse_create_cipher_payload(
    payload: Value,
) -> Result<(CipherRequestData, Vec<String>), AppError> {
    let wrapped = serde_json::from_value::<CreateCipherRequest>(payload.clone());

    match wrapped {
        Ok(req) => Ok((req.cipher, req.collection_ids)),
        Err(_) => {
            let flat = serde_json::from_value::<CipherRequestFlat>(payload)
                .map_err(|_| AppError::BadRequest("Invalid cipher payload".to_string()))?;
            Ok((flat.cipher, flat.collection_ids))
        }
    }
}

#[worker::send]
pub async fn create_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<Value>,
) -> Result<Json<Cipher>, AppError> {
    let (cipher, collection_ids) = parse_create_cipher_payload(payload)?;

    create_cipher_inner(claims, &env, cipher, collection_ids).await
}

#[worker::send]
pub async fn post_ciphers(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherRequestFlat>,
) -> Result<Json<Cipher>, AppError> {
    create_cipher_inner(claims, &env, payload.cipher, payload.collection_ids).await
}

#[worker::send]
pub async fn update_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing_cipher: crate::models::cipher::CipherDBModel = query!(
        &db,
        "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Cipher not found".to_string()))?;

    let cipher_data_req = payload;

    let cipher_data = CipherData {
        name: cipher_data_req.name,
        notes: cipher_data_req.notes,
        login: cipher_data_req.login,
        card: cipher_data_req.card,
        identity: cipher_data_req.identity,
        secure_note: cipher_data_req.secure_note,
        fields: cipher_data_req.fields,
        password_history: cipher_data_req.password_history,
        reprompt: cipher_data_req.reprompt,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let cipher = Cipher {
        id: id.clone(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite,
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: existing_cipher.deleted_at,
        created_at: existing_cipher.created_at,
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "UPDATE ciphers SET organization_id = ?1, type = ?2, data = ?3, favorite = ?4, folder_id = ?5, updated_at = ?6 WHERE id = ?7 AND user_id = ?8",
        cipher.organization_id,
        cipher.r#type,
        data,
        cipher.favorite,
        cipher.folder_id,
        cipher.updated_at,
        id,
        claims.sub,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn soft_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing = get_cipher_dbmodel(&env, &id, &claims.sub).await?;

    query!(
        &db,
        "UPDATE ciphers SET deleted_at = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
        now,
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let mut cipher: Cipher = existing.into();
    cipher.deleted_at = Some(now.clone());
    cipher.updated_at = now;
    Ok(Json(cipher))
}

#[worker::send]
pub async fn restore_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing = get_cipher_dbmodel(&env, &id, &claims.sub).await?;

    query!(
        &db,
        "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let mut cipher: Cipher = existing.into();
    cipher.deleted_at = None;
    cipher.updated_at = now;
    Ok(Json(cipher))
}

#[worker::send]
pub async fn hard_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;

    query!(
        &db,
        "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(()))
}

#[worker::send]
pub async fn hard_delete_cipher_post(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    hard_delete_cipher(claims, State(env), Path(id)).await
}

#[worker::send]
pub async fn soft_delete_ciphers(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    for id in payload.ids {
        query!(
            &db,
            "UPDATE ciphers SET deleted_at = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
            now,
            now,
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    }

    Ok(Json(()))
}

#[worker::send]
pub async fn restore_ciphers(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    for id in payload.ids {
        query!(
            &db,
            "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
            now,
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    }

    Ok(Json(()))
}

#[worker::send]
pub async fn hard_delete_ciphers(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;

    for id in payload.ids {
        query!(
            &db,
            "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    }

    Ok(Json(()))
}

#[worker::send]
pub async fn hard_delete_ciphers_delete(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    hard_delete_ciphers(claims, State(env), Json(payload)).await
}

#[cfg(test)]
mod tests {
    use super::parse_create_cipher_payload;
    use serde_json::json;

    #[test]
    fn parse_create_cipher_payload_accepts_wrapped_shape() {
        let payload = json!({
            "cipher": {
                "type": 1,
                "name": "enc-name",
                "favorite": false,
                "login": {"username": "enc-user", "password": "enc-pass"}
            },
            "collectionIds": ["c1"]
        });

        let (cipher, collections) =
            parse_create_cipher_payload(payload).expect("wrapped should parse");

        assert_eq!(cipher.r#type, 1);
        assert_eq!(cipher.name, "enc-name");
        assert_eq!(cipher.favorite, false);
        assert_eq!(collections, vec!["c1".to_string()]);
    }

    #[test]
    fn parse_create_cipher_payload_accepts_pascalcase_wrapped_shape() {
        let payload = json!({
            "Cipher": {
                "type": 1,
                "name": "enc-name",
                "favorite": false,
                "login": {"username": "enc-user", "password": "enc-pass"}
            },
            "CollectionIds": ["c1"]
        });

        let (cipher, collections) =
            parse_create_cipher_payload(payload).expect("pascal wrapped should parse");

        assert_eq!(cipher.r#type, 1);
        assert_eq!(cipher.name, "enc-name");
        assert_eq!(cipher.favorite, false);
        assert_eq!(collections, vec!["c1".to_string()]);
    }

    #[test]
    fn parse_create_cipher_payload_accepts_flat_shape() {
        let payload = json!({
            "type": 1,
            "name": "enc-name",
            "favorite": true,
            "login": {"username": "enc-user", "password": "enc-pass"},
            "collectionIds": ["c1", "c2"]
        });

        let (cipher, collections) =
            parse_create_cipher_payload(payload).expect("flat should parse");

        assert_eq!(cipher.r#type, 1);
        assert_eq!(cipher.name, "enc-name");
        assert_eq!(cipher.favorite, true);
        assert_eq!(collections, vec!["c1".to_string(), "c2".to_string()]);
    }

    #[test]
    fn parse_create_cipher_payload_accepts_int_favorite() {
        let payload = json!({
            "type": 1,
            "name": "enc-name",
            "favorite": 1,
            "login": {"username": "enc-user", "password": "enc-pass"}
        });

        let (cipher, collections) =
            parse_create_cipher_payload(payload).expect("int favorite should parse");

        assert_eq!(cipher.favorite, true);
        assert!(collections.is_empty());
    }

    #[test]
    fn parse_create_cipher_payload_rejects_invalid_shape() {
        let payload = json!({ "foo": "bar" });
        assert!(parse_create_cipher_payload(payload).is_err());
    }
}
