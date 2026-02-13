use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use worker::Env;

use crate::error::AppError;
use crate::jwt;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // User ID
    pub exp: usize,  // Expiration time
    pub nbf: usize,  // Not before time

    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub amr: Vec<String>,
    pub security_stamp: Option<String>,
}

impl FromRequestParts<Arc<Env>> for Claims
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<Env>) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|auth_header| auth_header.to_str().ok())
            .and_then(|auth_value| auth_value.strip_prefix("Bearer ").map(|stripped| stripped.to_owned()))
            .or_else(|| {
                let raw = parts.headers.get(header::COOKIE)?.to_str().ok()?;
                for part in raw.split(';') {
                    let part = part.trim();
                    if let Some((k, v)) = part.split_once('=') {
                        if k.trim() == "bw_access_token" {
                            return Some(v.trim().to_string());
                        }
                    }
                }
                None
            })
            .ok_or_else(|| AppError::Unauthorized("Missing or invalid token".to_string()))?;

        let secret = state.secret("JWT_SECRET")?;

        jwt::decode_hs256(&token, &secret.to_string())
    }
}
