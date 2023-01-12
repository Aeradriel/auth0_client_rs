use alcoholic_jwt::ValidationError;
use reqwest::Error as ReqwestError;
use serde::Deserialize;
use serde_json::Error as SerdeJsonError;
use thiserror::Error as ThisError;

use crate::users::UserError;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Auth0ApiError {
    pub status_code: i32,
    pub error: String,
    pub message: String,
    pub error_code: Option<String>,
}

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Missing kid in JWT")]
    JwtMissingKid,
    #[error("Invalid JWT: {0}")]
    InvalidJwt(#[from] ValidationError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerdeJsonError),
    #[error("Reqwest error: {0}")]
    Http(#[from] ReqwestError),
    #[error("Too many requests")]
    TooManyRequests,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("User error: {0}")]
    User(#[from] UserError),
    #[error("Unimplemented")]
    Unimplemented,
    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type Auth0Result<T> = Result<T, Error>;
