//! Types relative to error handling.

use reqwest::Error as ReqwestError;
use serde::Deserialize;
use serde_json::Error as SerdeJsonError;
use thiserror::Error as ThisError;

use crate::users::UserError;

/// The error type which represent an error returned by the Auth0 API.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Auth0ApiError {
    pub status_code: i32,
    pub error: String,
    pub message: String,
    pub error_code: Option<String>,
}

/// The error type which is returned if some error occurs duging a request.
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Missing kid in JWT")]
    JwtMissingKid,
    #[error("Invalid JWT: {0}")]
    InvalidJwt(#[from] jsonwebtoken::errors::Error),
    // this is an internal error and should be considered a bug. That's why I'm not returning any aditional info
    #[error("Invalid JWK")]
    InvalidJwk,
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
    #[error("Invalid response body")]
    InvalidResponseBody,
    #[error("Invalid username")]
    InvalidUsername,
    #[error("Invalid password")]
    InvalidPassword,
}

pub type Auth0Result<T> = Result<T, Error>;
