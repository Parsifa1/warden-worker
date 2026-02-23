use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

static ERROR_LIST: phf::Map<&'static str, ErrorListEntry> = phf::phf_map! {
    "invalid_username_or_password" => ErrorListEntry {
        error: "invalid_grant",
        message: "邮箱或密码错误，请重新输入",
    },
};

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Worker error: {0}")]
    Worker(#[from] worker::Error),

    #[error("Database query failed")]
    Database,

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[allow(dead_code)]
    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Internal server error")]
    Internal,

    #[error("Too many requests: {0}")]
    TooManyRequests(String),
}

#[derive(serde::Serialize)]
struct ErrorModel {
    #[serde(rename = "Message")]
    message: String,
    #[serde(rename = "Object")]
    object: String,
}

struct ErrorListEntry<'a> {
    error: &'a str,
    message: &'a str,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_description) = match self {
            AppError::Worker(e) => {
                log::error!("Worker error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            AppError::Database => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            ),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
            AppError::Crypto(msg) => {
                log::error!("Crypto error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            AppError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        let body = Json(json!({
            "error": ERROR_LIST[&error_description].error,
            "error_description": error_description,
            "ErrorModel": ErrorModel {
                message: ERROR_LIST[&error_description].message.to_string(),
                object: "error".to_string(),
            }
        }));
        (status, body).into_response()
    }
}
