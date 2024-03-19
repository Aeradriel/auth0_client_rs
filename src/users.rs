//! Types, traits and functions relative to the users API.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;

use crate::authorization::Authenticatable;
use crate::error::{Auth0ApiError, Auth0Result, Error};
use crate::{Auth0Client, GrantType};

/// A struct that can interact with the Auth0 users API.
#[async_trait]
pub trait OperateUsers {
    /// Gets a user through the Auth0 users API.
    ///
    /// # Arguments
    /// * `user_id` - The user ID of the user to get.
    ///
    /// # Example
    /// ```
    /// # async fn get_user(mut client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
    /// # use crate::auth0_client::users::OperateUsers;
    /// let user = client.get_user("auth0|63dadcecb564285db4445a75").await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_user(&mut self, user_id: &str) -> Auth0Result<UserResponse>;

    /// Gets a user through the Auth0 users API.
    ///
    /// # Arguments
    /// * `email` - The email of the user to get.
    /// * `connection` - The connection of the user to get.
    ///
    /// # Example
    /// ```
    /// # async fn get_user(mut client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
    /// # use crate::auth0_client::users::OperateUsers;
    /// let existing = client.get_user_by_email("test@example.com", "Username-Password-Authentication").await?;
    /// let not_existing = client.get_user_by_email("random@example.com", "Username-Password-Authentication").await?;
    ///
    /// assert!(existing.is_some());
    /// assert!(not_existing.is_none());
    /// # Ok(())
    /// # }
    /// ```
    ///
    async fn get_user_by_email(
        &mut self,
        email: &str,
        connection: &str,
    ) -> Auth0Result<Option<UserResponse>>;

    /// Creates a user through the Auth0 users API.
    ///
    /// # Arguments
    /// * `payload` - A struct containing the necessary information to create a user.
    ///
    /// The `connection` field is mandatory, others depends on the connection type.
    ///
    /// # Example
    /// ```
    /// # async fn create_user(mut client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
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
    /// * `user_id` - The user ID of the user to update.
    /// * `payload` - A struct containing the necessary information to update a user.
    ///
    /// # Example
    /// ```
    /// # async fn update_user(mut client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
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

    /// Deletes a user through the Auth0 users API.
    ///
    /// # Arguments
    /// * `user_id` - The user ID of the user to delete.
    ///
    /// # Example
    /// ```
    /// # async fn delete_user(mut client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
    /// # use crate::auth0_client::users::OperateUsers;
    ///
    /// let resp = client
    ///     .delete_user("auth0|63bfd5cdbd7f2c642dd83768")
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn delete_user(&mut self, user_id: &str) -> Auth0Result<()>;

    /// Check a user's password through the Auth0 users API.
    ///
    /// # Arguments
    /// * `payload` - A struct containing the necessary information to check the user's passord.
    ///
    /// The `connection` field is mandatory, others depends on the connection type.
    ///
    /// # Example
    /// ```
    /// # async fn check_password(mut client: auth0_client::Auth0Client) -> auth0_client::error::Auth0Result<()> {
    /// # use crate::auth0_client::users::OperateUsers;
    /// let mut payload =
    ///     auth0_client::users::CheckPasswordPayload::new();
    /// payload.username = "test@example.com".to_owned();
    /// payload.password = "password123456789!".to_owned();
    ///
    /// client.check_password(&payload).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn check_password(&mut self, payload: &CheckPasswordPayload) -> Auth0Result<()>;
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

/// A struct containing the payload for checking a user's password.
#[derive(Default, Serialize)]
pub struct CheckPasswordPayload {
    pub username: String,
    pub password: String,
}

/// A struct containing the response from the Auth0 users API.
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
pub struct Identity {
    pub connection: String,
    pub user_id: String,
    pub provider: String,
    #[serde(rename = "isSocial")]
    pub is_social: bool,
}

#[async_trait]
impl OperateUsers for Auth0Client {
    async fn get_user(&mut self, user_id: &str) -> Auth0Result<UserResponse> {
        self.request::<_, _, UserError>(Method::GET, &format!("/users/{user_id}"), None::<String>)
            .await?
            .ok_or(Error::InvalidResponseBody)
    }

    async fn get_user_by_email(
        &mut self,
        email: &str,
        connection: &str,
    ) -> Auth0Result<Option<UserResponse>> {
        let res: Vec<UserResponse> = self
            .request::<_, _, UserError>(
                Method::GET,
                &format!(
                    "/users?connection={connection}&q=email%3A{}&search_engine=v3",
                    urlencoding::encode(email)
                ),
                None::<String>,
            )
            .await?
            .ok_or(Error::InvalidResponseBody)?;

        let user = res
            .iter()
            .find(|u| u.identities.iter().any(|i| i.connection == connection))
            .cloned();

        Ok(user)
    }

    async fn create_user(&mut self, payload: &CreateUserPayload) -> Auth0Result<UserResponse> {
        self.request::<_, _, UserError>(Method::POST, "/users", Some(payload))
            .await?
            .ok_or(Error::InvalidResponseBody)
    }

    async fn update_user(
        &mut self,
        user_id: &str,
        payload: &UpdateUserPayload,
    ) -> Auth0Result<UserResponse> {
        self.request::<_, _, UserError>(Method::PATCH, &format!("/users/{user_id}"), Some(payload))
            .await?
            .ok_or(Error::InvalidResponseBody)
    }

    async fn delete_user(&mut self, user_id: &str) -> Auth0Result<()> {
        self.request::<_, (), UserError>(
            Method::DELETE,
            &format!("/users/{user_id}"),
            None::<String>,
        )
        .await?;
        Ok(())
    }

    async fn check_password(&mut self, payload: &CheckPasswordPayload) -> Auth0Result<()> {
        self.grant_type(GrantType::Password);

        self.authenticate_user(payload.username.clone(), payload.password.clone())
            .await?;

        Ok(())
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

impl CheckPasswordPayload {
    /// Returns an empty payload for user password checking.
    pub fn new() -> Self {
        Self::default()
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

    mod get_user {
        use super::*;

        fn get_user_mock() -> Mock {
            mock("GET", "/users/1234")
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
            let _m = get_user_mock();
            let mut client = new_client();

            let resp = client.get_user("1234").await.unwrap();

            assert_eq!(resp.email, Some("test@example.com".to_owned()));
        }
    }

    mod get_user_by_email {
        use super::*;

        fn get_user_by_email_mock() -> Mock {
            mock("GET", format!("/users?connection=Username-Password-Authentication&q=email%3A{}&search_engine=v3", urlencoding::encode("test@example.com")).as_str())
                .with_status(200)
                .with_body(
                    json!([{
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
                      }]).to_string(),
                )
                .create()
        }

        fn get_user_by_email_not_found_mock() -> Mock {
            mock("GET", format!("/users?connection=Username-Password-Authentication&q=email%3A{}&search_engine=v3", urlencoding::encode("test@example.com")).as_str())
                .with_status(200)
                .with_body(json!([]).to_string())
                .create()
        }

        #[tokio::test]
        async fn works_with_sample_response() {
            let _m = get_user_by_email_mock();
            let mut client = new_client();

            let resp = client
                .get_user_by_email("test@example.com", "Username-Password-Authentication")
                .await
                .unwrap()
                .unwrap();

            assert_eq!(resp.email, Some("test@example.com".to_owned()));
        }

        #[tokio::test]
        async fn works_with_not_found() {
            let _m = get_user_by_email_not_found_mock();
            let mut client = new_client();

            let resp = client
                .get_user_by_email("test@example.com", "Username-Password-Authentication")
                .await
                .unwrap();

            assert!(resp.is_none());
        }
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

        fn update_user_mock() -> Mock {
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
            let _m = update_user_mock();
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

    mod delete_user {
        use super::*;

        fn delete_user_mock() -> Mock {
            mock("DELETE", "/users/auth0|63bfd5cdbd7f1c642dd83768")
                .with_status(204)
                .create()
        }

        #[tokio::test]
        async fn works_with_sample_response() {
            let _m = delete_user_mock();
            let mut client = new_client();

            client
                .delete_user("auth0|63bfd5cdbd7f1c642dd83768")
                .await
                .unwrap();
        }
    }

    mod check_password {
        use super::*;

        fn check_password_mock() -> Mock {
            mock("POST", "/oauth/token")
                .with_status(200)
                .with_body(
                    json!({
                      "access_token": "ACCESS_TOKEN",
                      "refresh_token": "REFRESH_TOKEN",
                      "id_token": "ID_TOKEN",
                      "token_type": "TOKEN_TYPE",
                      "expires_in": 3600
                    })
                    .to_string(),
                )
                .create()
        }

        #[tokio::test]
        async fn works_with_sample_response() {
            let _m = check_password_mock();
            let mut client = new_client();

            let mut payload = CheckPasswordPayload::new();
            payload.username = "test@example.com".to_owned();
            payload.password = "password123456789!".to_owned();

            client.check_password(&payload).await.unwrap();
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
