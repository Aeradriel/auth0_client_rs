//! # auth0_client_rs
//! [![CI](https://github.com/Aeradriel/auth0_client_rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Aeradriel/auth0_client_rs/actions/workflows/ci.yml) [![codecov](https://codecov.io/gh/Aeradriel/auth0_client_rs/branch/master/graph/badge.svg?token=46STM1E4U5)](https://codecov.io/gh/Aeradriel/auth0_client_rs)
//!
//! This crates allow to interact with the Auth0 API.
//! It is still a work in progress and therefore misses lot of functionnalities.
//!
//! ## Installation
//!
//! Add this line to your `Cargo.toml`:
//!
//! ```Toml
//! [dependencies]
//! auth0_client = "0.1.0"
//! ```
//!
//! ## Usage overview
//!
//! ```rust
//! # async fn run() -> auth0_client::error::Auth0Result<()> {
//! # use auth0_client::users::CreateUserPayload;
//! # use auth0_client::Auth0Client;
//! # use auth0_client::users::OperateUsers;
//! # use auth0_client::authorization::Authenticatable;
//! let mut client = Auth0Client::new(
//!     "client_id",
//!     "client_secret",
//!     "http://domain.com",
//!     "http://audience.com",
//! );
//!
//! client.authenticate().await?;
//!
//! let mut payload =
//!     CreateUserPayload::from_connection("Username-Password-Authentication");
//! payload.email = Some("test@example.com".to_owned());
//! payload.password = Some("password123456789!".to_owned());
//!
//! let new_user = client.create_user(&payload).await;
//! # Ok(())
//! # }
//! ```

#[cfg(all(feature = "jsonwebtoken", feature = "alcoholic_jwt"))]
compile_error!(
    "Can't enable `jsonwebtoken` and `alcoholic_jwt`. To enable `jsonwebtoken`, disable default features."
);

#[cfg(not(any(feature = "jsonwebtoken", feature = "alcoholic_jwt")))]
compile_error!("Either `jsonwebtoken` or `alcoholic_jwt` has to be enabled.");

#[cfg(all(feature = "tracing", feature = "log"))]
compile_error!("Can't enable `tracing` and `log`. To enable `tracing`, disable default features.");

#[cfg(not(any(feature = "tracing", feature = "tracing")))]
compile_error!("Either `tracing` or `log` has to be enabled.");

use error::{Auth0ApiError, Auth0Result, Error};
use reqwest::{Client as ReqwestClient, Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Display;
use utils::{complete_validations, JwkSet};

use crate::authorization::{valid_jwt, Authenticatable};

pub mod authorization;
pub mod error;
pub mod users;
mod utils;

use crate::utils::{log, URL_REGEX};

/// The grant type to use when authenticating.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    ClientCredentials,
    Password,
}

/// The client used to make requests towards the Auth0 API.
pub struct Auth0Client {
    client_id: String,
    client_secret: String,
    domain: String,
    audience: String,
    grant_type: GrantType,
    access_token: Option<String>,
    http_client: ReqwestClient,
    jwks: Option<JwkSet>,
}

impl Auth0Client {
    /// Creates a new client from given configuration.
    pub fn new(client_id: &str, client_secret: &str, domain: &str, audience: &str) -> Auth0Client {
        Auth0Client {
            client_id: client_id.to_owned(),
            client_secret: client_secret.to_owned(),
            domain: domain.to_owned(),
            audience: audience.to_owned(),
            grant_type: GrantType::ClientCredentials,
            access_token: None,
            http_client: ReqwestClient::new(),
            jwks: None,
        }
    }

    /// Get a reference to the stored JWKS
    pub fn jwks(&self) -> Option<&JwkSet> {
        self.jwks.as_ref()
    }

    /// Set the JWKS
    pub fn set_jwks(&mut self, jwks: JwkSet) {
        self.jwks = Some(jwks);
    }

    /// Sets the grant type for the client.
    pub fn grant_type(&mut self, grant_type: GrantType) -> &Auth0Client {
        self.grant_type = grant_type;
        self
    }

    /// Make a request towards the Auth0 API. It uses the `audience` field as the base URL.
    ///
    /// If access token is expired, it will first try to get a new one.
    ///
    /// # Parameters
    ///
    /// * `method`: The HTTP method to use.
    /// * `path`: The path to use for the request.
    /// * `body`: The body to send with the request.
    ///
    /// # Example
    ///
    /// ```rust
    /// # async fn create_user(mut client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
    /// # use crate::auth0_client::users::OperateUsers;
    /// # use auth0_client::users::UserError;
    /// # use auth0_client::users::UserResponse;
    /// client.request::<String, UserResponse, UserError>(reqwest::Method::GET, "/api/v2/users", None).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn request<B, R, E>(
        &mut self,
        method: Method,
        path: &str,
        body: Option<B>,
    ) -> Auth0Result<Option<R>>
    where
        B: Serialize,
        R: DeserializeOwned,
        E: From<Auth0ApiError> + Into<Error>,
    {
        let url = URL_REGEX
            .replace_all(&format!("{}/{path}", self.audience), "$1")
            .to_string();

        log::debug!("Starting {method} request at {url}...");

        let mut req = match method {
            Method::GET => self.http_client.get(&url),
            Method::POST => self.http_client.post(&url),
            Method::PATCH => self.http_client.patch(&url),
            Method::DELETE => self.http_client.delete(&url),
            _ => return Err(Error::Unimplemented),
        };

        if let Some(mut access_token) = self.access_token.clone() {
            // Check validity of stored token.
            let validations = complete_validations(&self.domain, &self.audience);
            let stored_token =
                valid_jwt(&access_token, &self.domain, validations, self.jwks.as_ref()).await;

            match stored_token {
                Ok((_, jwks)) => self.jwks = Some(jwks),
                Err(e) => {
                    log::debug!("Stored access token is invalid: {}", e.to_string());
                    log::debug!("Trying to get a new one...");

                    // Token is invalid so we try to get a new one once.
                    access_token = self.authenticate().await?;
                }
            }

            req = req.header("Authorization", format!("Bearer {access_token}"));
        }

        if let Some(body) = body {
            req = req.json(&body)
        }

        let response = req.send().await?;
        let status = response.status();
        let resp_body = response.text().await?;

        log::debug!("Response from Auth0 ({}): {resp_body}", status.as_u16());

        if status.is_success() {
            if status == StatusCode::NO_CONTENT {
                Ok(None)
            } else {
                Ok(Some(serde_json::from_str::<R>(&resp_body)?))
            }
        } else {
            match status {
                StatusCode::TOO_MANY_REQUESTS => Err(Error::TooManyRequests),
                StatusCode::UNAUTHORIZED => Err(Error::Unauthorized),
                _ => {
                    let err: E = serde_json::from_str::<Auth0ApiError>(&resp_body)?.into();

                    Err(err.into())
                }
            }
        }
    }
}

impl Display for GrantType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantType::ClientCredentials => write!(f, "client_credentials"),
            GrantType::Password => write!(f, "password"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_client() -> Auth0Client {
        Auth0Client::new(
            "client_id",
            "client_secret",
            "https://domain.com",
            "https://audience.com",
        )
    }

    mod new {
        use super::*;

        #[test]
        fn return_a_client() {
            let client = new_client();

            assert_eq!(&client.client_id, "client_id");
            assert_eq!(&client.client_secret, "client_secret");
            assert_eq!(&client.domain, "https://domain.com");
            assert_eq!(&client.audience, "https://audience.com");
            assert_eq!(client.grant_type, GrantType::ClientCredentials);
        }
    }

    mod grant_type {
        use super::*;

        #[test]
        fn set_the_grant_type() {
            let mut client = new_client();
            client.grant_type(GrantType::Password);

            assert_eq!(client.grant_type, GrantType::Password);
        }
    }

    mod request {
        use super::*;

        fn new_client() -> Auth0Client {
            Auth0Client::new(
                "client_id",
                "client_secret",
                &mockito::server_url(),
                &mockito::server_url(),
            )
        }

        mod errors {
            use super::*;

            use crate::users::UserError;

            #[tokio::test]
            async fn too_many_requests() {
                let mut client = new_client();
                let _mock = mockito::mock("GET", "/test").with_status(429).create();
                let response = client
                    .request::<(), (), UserError>(Method::GET, "/test", None)
                    .await;

                match response {
                    Err(Error::TooManyRequests) => (),
                    _ => panic!("Expected TooManyRequests variant, got: {response:?}"),
                }
            }

            #[tokio::test]
            async fn unauthorized() {
                let mut client = new_client();
                let _mock = mockito::mock("GET", "/").with_status(401).create();
                let response = client
                    .request::<(), (), UserError>(Method::GET, "/", None)
                    .await;

                match response {
                    Err(Error::Unauthorized) => (),
                    _ => panic!("Expected Unauthorized variant, got: {response:?}"),
                }
            }
        }
    }
}
