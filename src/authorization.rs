use alcoholic_jwt::{token_kid, validate, ValidJWT, Validation, JWKS};
use async_trait::async_trait;
use serde::Deserialize;

use crate::error::{Auth0Result, Error};
use crate::Auth0Client;

#[async_trait]
pub trait Authenticatable {
    async fn authenticate(&mut self) -> Auth0Result<()>;
    fn access_token(&self) -> Option<String>;
}

#[derive(Deserialize)]
enum TokenType {
    Bearer,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct AccessTokenResponse {
    pub access_token: String,
}

#[async_trait]
impl Authenticatable for Auth0Client {
    async fn authenticate(&mut self) -> Auth0Result<()> {
        let url = format!("{}/oauth/token", self.domain).replace("//", "/");

        log::debug!("Starting authentication at {url}...");

        let body = {
            let mut body = std::collections::HashMap::new();

            body.insert("grant_type", self.grant_type.to_string());
            body.insert("client_id", self.client_id.clone());
            body.insert("client_secret", self.client_secret.clone());
            body.insert("audience", self.audience.clone());
            body
        };

        let response = self.http_client.post(&url).json(&body).send().await?;
        let status = response.status();
        let resp_body = response.text().await?;

        log::debug!("Response from Auth0 ({}): {resp_body}", status.as_u16());

        let response = serde_json::from_str::<AccessTokenResponse>(&resp_body)?;

        self.access_token = Some(response.access_token);
        Ok(())
    }

    fn access_token(&self) -> Option<String> {
        self.access_token.clone()
    }
}

async fn fetch_jwks(uri: &str) -> Auth0Result<JWKS> {
    let res = reqwest::get(uri).await?;
    let val = res.json::<JWKS>().await?;

    Ok(val)
}

pub async fn valid_jwt(
    token: &str,
    authority: &str,
    validations: Vec<Validation>,
) -> Auth0Result<ValidJWT> {
    let jwks = fetch_jwks(&format!("{authority}/.well-known/jwks.json")).await?;
    let kid = match token_kid(token) {
        Ok(res) => res.expect("failed to decode kid"),
        Err(_) => return Err(Error::JwtMissingKid),
    };
    let jwk = jwks.find(&kid).ok_or(Error::JwtMissingKid)?;
    let res = validate(token, jwk, validations)?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use mockito::{mock, Mock};
    use serde_json::json;

    use super::*;

    fn new_client() -> Auth0Client {
        Auth0Client::new(
            "client_id",
            "client_secret",
            &mockito::server_url(),
            "https://audience.com",
        )
    }

    fn auth_mock() -> Mock {
        mock("POST", "/oauth/token")
            .with_status(200)
            .with_body(
                json!({ "access_token": "access_token", "token_type": "Bearer" }).to_string(),
            )
            .create()
    }

    mod authenticate {
        use super::*;

        #[tokio::test]
        async fn save_the_access_token_to_the_client() {
            let _m = auth_mock();
            let mut client = new_client();

            client.authenticate().await.unwrap();
            assert_eq!(client.access_token, Some("access_token".to_owned()));
        }
    }

    mod access_token {
        use super::*;

        #[test]
        fn return_none_when_not_authenticated() {
            let _m = auth_mock();
            let client = new_client();

            assert_eq!(client.access_token(), None);
        }

        #[tokio::test]
        async fn return_access_token_when_authenticated() {
            let _m = auth_mock();
            let mut client = new_client();

            client.authenticate().await.unwrap();
            assert_eq!(client.access_token(), Some("access_token".to_owned()));
        }
    }

    mod jwt_validation {
        use super::*;

        fn jwks_mock() -> Mock {
            let jwks_response = std::fs::read_to_string("tests/data/jwks.json").unwrap();

            mock("GET", "/.well-known/jwks.json")
                .with_status(200)
                .with_body(jwks_response)
                .create()
        }

        mod fetch_jwks {
            use super::*;

            #[tokio::test]
            async fn works_with_sample_response() {
                let _m = jwks_mock();

                fetch_jwks(&format!("{}/.well-known/jwks.json", mockito::server_url()))
                    .await
                    .unwrap();
            }
        }

        mod valid_jwt {
            use alcoholic_jwt::ValidationError;

            use super::*;

            #[tokio::test]
            async fn validate_valid_jwt() {
                let _m = jwks_mock();
                let valid_token = std::fs::read_to_string("tests/data/valid_jwt.txt").unwrap();

                valid_jwt(
                    &valid_token,
                    &mockito::server_url(),
                    vec![Validation::SubjectPresent],
                )
                .await
                .unwrap();
            }

            #[tokio::test]
            async fn errored_with_missing_kid() {
                let jwks_response = std::fs::read_to_string("tests/data/jwks_no_key.json").unwrap();
                let _m = mock("GET", "/.well-known/jwks.json")
                    .with_status(200)
                    .with_body(jwks_response)
                    .create();
                let valid_token = std::fs::read_to_string("tests/data/valid_jwt.txt").unwrap();
                let res = valid_jwt(
                    &valid_token,
                    &mockito::server_url(),
                    vec![Validation::SubjectPresent],
                )
                .await;

                match res {
                    Err(Error::JwtMissingKid) => (),
                    Err(err) => panic!("Expected JWTError(InvalidSignature) but got {err:?}"),
                    _ => panic!("Expected JWTError but got a valid JWT"),
                }
            }

            #[tokio::test]
            async fn errored_with_invalid_jwt() {
                let _m = jwks_mock();
                let invalid_token = std::fs::read_to_string("tests/data/invalid_jwt.txt").unwrap();
                let res = valid_jwt(
                    &invalid_token,
                    &mockito::server_url(),
                    vec![Validation::SubjectPresent],
                )
                .await;

                match res {
                    Err(Error::InvalidJwt(ValidationError::InvalidSignature)) => (),
                    Err(err) => panic!("Expected JWTError(InvalidSignature) but got {err:?}"),
                    _ => panic!("Expected JWTError but got a valid JWT"),
                }
            }
        }
    }
}
