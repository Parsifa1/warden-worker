use axum::{
    extract::{Path, State},
    response::{IntoResponse, Redirect, Response},
};
use std::sync::Arc;
use worker::Env;

use crate::error::AppError;

#[worker::send]
pub async fn get_icon(
    State(_env): State<Arc<Env>>,
    Path(path): Path<String>,
) -> Result<Response, AppError> {
    let domain = path
        .strip_suffix("/icon.png")
        .unwrap_or(&path);

    let target_url = format!("https://vault.bitwarden.com/icons/{}/icon.png", domain);

    // Redirect directly to Bitwarden icon host to avoid proxy fetch/copy in Worker.
    let mut response = Redirect::temporary(&target_url).into_response();

    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("public, max-age=604800, immutable"),
    );

    Ok(response)
}
