# auth0_client
[![CI](https://github.com/Aeradriel/auth0_client_rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Aeradriel/auth0_client_rs/actions/workflows/ci.yml) [![codecov](https://codecov.io/gh/Aeradriel/auth0_client_rs/branch/master/graph/badge.svg?token=46STM1E4U5)](https://codecov.io/gh/Aeradriel/auth0_client_rs)

This crates allow to interact with the Auth0 API.
It is still a work in progress and therefore misses lot of functionnalities.

## Installation

Add this line to your `Cargo.toml`:

```Toml
[dependencies]
auth0_client = "0.1.0"
```

## Usage overview

```rust
let mut client = Auth0Client::new(
    "client_id",
    "client_secret",
    "http://domain.com",
    "http://audience.com",
);

client.authenticate().await?;

let mut payload =
    CreateUserPayload::from_connection("Username-Password-Authentication");
payload.email = Some("test@example.com".to_owned());
payload.password = Some("password123456789!".to_owned());

let new_user = client.create_user(&payload).await;
```
