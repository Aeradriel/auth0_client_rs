use std::fmt::Display;

use error::{Auth0ApiError, Auth0Result, Error};
use reqwest::{Client as ReqwestClient, Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::utils::URL_REGEX;

pub mod authorization;
pub mod error;
pub mod users;
mod utils;

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    ClientCredentials,
}

pub struct Auth0Client {
    client_id: String,
    client_secret: String,
    domain: String,
    audience: String,
    grant_type: GrantType,
    access_token: Option<String>,
    http_client: ReqwestClient,
}

impl Auth0Client {
    pub fn new(client_id: &str, client_secret: &str, domain: &str, audience: &str) -> Auth0Client {
        Auth0Client {
            client_id: client_id.to_owned(),
            client_secret: client_secret.to_owned(),
            domain: domain.to_owned(),
            audience: audience.to_owned(),
            grant_type: GrantType::ClientCredentials,
            access_token: None,
            http_client: ReqwestClient::new(),
        }
    }

    pub fn grant_type(mut self, grant_type: GrantType) -> Auth0Client {
        self.grant_type = grant_type;
        self
    }

    pub async fn request<B, R, E>(
        &self,
        method: Method,
        path: &str,
        body: Option<B>,
    ) -> Auth0Result<R>
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
            _ => return Err(Error::Unimplemented),
        };

        if let Some(access_token) = &self.access_token {
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
            serde_json::from_str::<R>(&resp_body).map_err(Into::into)
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
            let client = new_client().grant_type(GrantType::ClientCredentials);

            assert_eq!(client.grant_type, GrantType::ClientCredentials);
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
                let client = new_client();
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
                let client = new_client();
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
