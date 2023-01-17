//! Types, traits and functions relative to the users API.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;

use crate::error::{Auth0ApiError, Auth0Result};
use crate::Auth0Client;

/// A struct that can interact with the Auth0 users API.
#[async_trait]
pub trait OperateUsers {
    /// Creates a user through the Auth0 users API.
    ///     
    /// # Arguments
    ///
    /// * `payload` - A struct containing the necessary information to create a user.
    ///
    /// The `connection` field is mandatory, others depends on the connection type.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn create_user(client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
    /// # use crate::auth0_client::users::OperateUsers;
    /// let mut payload =
    ///     auth0_client::users::CreateUserPayload::from_connection("Username-Password-Authentication");
    /// payload.email = Some("test@example.com".to_owned());
    /// payload.password = Some("password123456789!".to_owned());
    ///
    /// let new_user = client.create_user(&payload).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn create_user(&mut self, payload: &CreateUserPayload) -> Auth0Result<UserResponse>;
    /// Updates a user through the Auth0 users API.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID of the user to update.
    /// * `payload` - A struct containing the necessary information to update a user.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn update_user(client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
    /// # use crate::auth0_client::users::OperateUsers;
    /// let mut payload =
    ///     auth0_client::users::UpdateUserPayload::from_connection("Username-Password-Authentication");
    /// payload.password = Some("password123456789!".to_owned());
    ///
    /// let resp = client
    ///     .update_user("auth0|63bfd5cdbd7f2c642dd83768", &payload)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn update_user(
        &mut self,
        user_id: &str,
        payload: &UpdateUserPayload,
    ) -> Auth0Result<UserResponse>;
}

/// A struct containing the payload for creating a user.
#[derive(Serialize)]
pub struct CreateUserPayload {
    pub connection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// A struct containing the payload for updating a user.
#[derive(Serialize)]
pub struct UpdateUserPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_email: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_phone_number: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// A struct containing the response from the Auth0 users API.
#[derive(Debug, Deserialize)]
pub struct UserResponse {
    pub user_id: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: String,
    pub nickname: String,
    pub picture: String,
    pub identities: Vec<Identity>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A struct containing an identity of a user.
#[derive(Debug, Deserialize)]
pub struct Identity {
    pub connection: String,
    pub user_id: String,
    pub provider: String,
    #[serde(rename = "isSocial")]
    pub is_social: bool,
}

#[async_trait]
impl OperateUsers for Auth0Client {
    async fn create_user(&mut self, payload: &CreateUserPayload) -> Auth0Result<UserResponse> {
        self.request::<_, _, UserError>(Method::POST, "/users", Some(payload))
            .await
    }

    async fn update_user(
        &mut self,
        user_id: &str,
        payload: &UpdateUserPayload,
    ) -> Auth0Result<UserResponse> {
        self.request::<_, _, UserError>(Method::PATCH, &format!("/users/{user_id}"), Some(payload))
            .await
    }
}

/// An error representing the possible errors that can occur when interacting with the Auth0 users API.
#[derive(Debug, ThisError)]
pub enum UserError {
    #[error("Invalid request body: {0}")]
    InvalidRequestBody(String),
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Connection not found")]
    ConnectionNotFound,
    #[error("Unknown user error: {0}")]
    Unknown(String),
}

impl From<Auth0ApiError> for UserError {
    fn from(api_error: Auth0ApiError) -> Self {
        match api_error.error_code.as_deref() {
            Some("invalid_body") => Self::InvalidRequestBody(api_error.message),
            Some("auth0_idp_error") => Self::UserAlreadyExists,
            Some("inexistent_connection") => Self::ConnectionNotFound,
            _ => Self::Unknown(api_error.message),
        }
    }
}

impl UpdateUserPayload {
    /// Returns an empty payload for user creation with only `connection` field set.
    ///
    /// # Arguments
    ///
    /// * `connection` - The connection type for the user we want to create.
    pub fn from_connection(connection: &str) -> Self {
        Self {
            connection: Some(connection.to_owned()),
            email: None,
            phone_number: None,
            user_metadata: None,
            blocked: None,
            email_verified: None,
            phone_verified: None,
            app_metadata: None,
            given_name: None,
            family_name: None,
            name: None,
            nickname: None,
            picture: None,
            password: None,
            username: None,
            verify_email: None,
            verify_phone_number: None,
            client_id: None,
        }
    }
}

impl CreateUserPayload {
    /// Returns an empty payload for user update with only `connection` field set.
    ///
    /// # Arguments
    ///
    /// * `connection` - The connection type for the user we want to update.
    pub fn from_connection(connection: &str) -> Self {
        Self {
            connection: connection.to_owned(),
            email: None,
            phone_number: None,
            user_metadata: None,
            blocked: None,
            email_verified: None,
            phone_verified: None,
            app_metadata: None,
            given_name: None,
            family_name: None,
            name: None,
            nickname: None,
            picture: None,
            user_id: None,
            password: None,
            username: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{mock, Mock};
    use serde_json::json;

    fn new_client() -> Auth0Client {
        Auth0Client::new(
            "client_id",
            "client_secret",
            &mockito::server_url(),
            &mockito::server_url(),
        )
    }

    mod create_user {
        use super::*;

        fn create_user_mock() -> Mock {
            mock("POST", "/users")
                .with_status(200)
                .with_body(
                    json!({
                        "created_at": "2023-01-12T09:24:45.761Z",
                        "email": "test@example.com",
                        "email_verified": false,
                        "identities": [
                          {
                            "connection": "Username-Password-Authentication",
                            "user_id": "63bfd5cdbd7f1c642dd83768",
                            "provider": "auth0",
                            "isSocial": false
                          }
                        ],
                        "name": "test@example.com",
                        "nickname": "test",
                        "picture": "https://s.gravatar.com/avatar/108cfa0160355a6aef1acdaa4493755c?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fth.png",
                        "updated_at": "2023-01-12T09:24:45.761Z",
                        "user_id": "auth0|63bfd5cdbd7f1c642dd83768"
                      }).to_string(),
                )
                .create()
        }

        #[tokio::test]
        async fn works_with_sample_response() {
            let _m = create_user_mock();
            let mut client = new_client();

            let mut payload =
                CreateUserPayload::from_connection("Username-Password-Authentication");
            payload.email = Some("test@example.com".to_owned());
            payload.password = Some("password123456789!".to_owned());

            let resp = client.create_user(&payload).await.unwrap();

            assert_eq!(resp.email, Some("test@example.com".to_owned()));
        }
    }

    mod update_user {
        use super::*;

        fn create_user_mock() -> Mock {
            mock("PATCH", "/users/auth0|63bfd5cdbd7f1c642dd83768")
                .with_status(200)
                .with_body(
                    json!({
                        "created_at": "2023-01-12T09:24:45.761Z",
                        "email": "test@example.com",
                        "email_verified": false,
                        "identities": [
                          {
                            "connection": "Username-Password-Authentication",
                            "user_id": "63bfd1ddbd7f1c635dd83768",
                            "provider": "auth0",
                            "isSocial": false
                          }
                        ],
                        "name": "test@example.com",
                        "nickname": "test",
                        "picture": "https://s.gravatar.com/avatar/108cfa0160355a6aef1acdaa4493755c?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fth.png",
                        "updated_at": "2023-01-12T09:24:45.761Z",
                        "user_id": "auth0|63bfd1ddbd7f1c635dd83768"
                      }).to_string(),
                )
                .create()
        }

        #[tokio::test]
        async fn works_with_sample_response() {
            let _m = create_user_mock();
            let mut client = new_client();

            let mut payload =
                UpdateUserPayload::from_connection("Username-Password-Authentication");
            payload.password = Some("password123456789!".to_owned());

            let resp = client
                .update_user("auth0|63bfd5cdbd7f1c642dd83768", &payload)
                .await
                .unwrap();

            assert_eq!(resp.email, Some("test@example.com".to_owned()));
        }
    }

    mod errors {
        use super::*;

        use crate::error::Error;

        #[tokio::test]
        async fn error_mapping_in_request() {
            let _m = mock("POST", "/users")
                .with_status(400)
                .with_body(
                    json!({
                      "statusCode": 400,
                      "error": "Bad Request",
                      "message": "The \"connection\" field is required.",
                      "errorCode": "invalid_body"
                    })
                    .to_string(),
                )
                .create();
            let mut client = new_client();

            let mut payload =
                CreateUserPayload::from_connection("Username-Password-Authentication");
            payload.email = Some("test@example.com".to_owned());
            payload.password = Some("password123456789!".to_owned());

            let resp = client.create_user(&payload).await;

            match resp {
                Err(Error::User(UserError::InvalidRequestBody(msg))) => {
                    assert_eq!(msg, "The \"connection\" field is required.")
                }
                _ => panic!("Invalid error"),
            }
        }

        #[test]
        fn from_auth0_api_error_to_user_error() {
            // Invalid body
            let auth0_error = Auth0ApiError {
                status_code: 400,
                error: "Bad Request".to_owned(),
                message: "\"password\" is required".to_owned(),
                error_code: Some("invalid_body".to_owned()),
            };

            match UserError::from(auth0_error) {
                UserError::InvalidRequestBody(msg) => assert_eq!(msg, "\"password\" is required"),
                _ => panic!("Invalid variant for error"),
            }

            // User already exists
            let auth0_error = Auth0ApiError {
                status_code: 400,
                error: "Conflict".to_owned(),
                message: "The user already exists.".to_owned(),
                error_code: Some("auth0_idp_error".to_owned()),
            };

            match UserError::from(auth0_error) {
                UserError::UserAlreadyExists => (),
                _ => panic!("Invalid variant for error"),
            }

            // Invalid connection
            let auth0_error = Auth0ApiError {
                status_code: 400,
                error: "Bad Request".to_owned(),
                message: "The connection does not exist.".to_owned(),
                error_code: Some("inexistent_connection".to_owned()),
            };

            match UserError::from(auth0_error) {
                UserError::ConnectionNotFound => (),
                _ => panic!("Invalid variant for error"),
            }

            // User already exists
            let auth0_error = Auth0ApiError {
                status_code: 400,
                error: "Bad Request".to_owned(),
                message: "Unknown error.".to_owned(),
                error_code: None,
            };

            match UserError::from(auth0_error) {
                UserError::Unknown(msg) => assert_eq!(msg, "Unknown error."),
                _ => panic!("Invalid variant for error"),
            }
        }
    }
}
