use crate::error::Auth0Result;
use crate::error::Error;
use lazy_static::lazy_static;
use regex::Regex;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Claims {}

#[cfg(feature = "jsonwebtoken")]
pub type JwkSet = jsonwebtoken::jwk::JwkSet;
#[cfg(feature = "alcoholic_jwt")]
pub type JwkSet = alcoholic_jwt::JWKS;

#[cfg(feature = "jsonwebtoken")]
pub type Jwk = jsonwebtoken::jwk::Jwk;
#[cfg(feature = "alcoholic_jwt")]
pub type Jwk = alcoholic_jwt::JWK;

#[cfg(feature = "jsonwebtoken")]
pub type ValidJwt = jsonwebtoken::TokenData<Claims>;
#[cfg(feature = "alcoholic_jwt")]
pub type ValidJwt = alcoholic_jwt::ValidJWT;

#[cfg(feature = "jsonwebtoken")]
pub type Validations = jsonwebtoken::Validation;
#[cfg(feature = "alcoholic_jwt")]
pub type Validations = Vec<alcoholic_jwt::Validation>;

#[cfg(feature = "jsonwebtoken")]
pub fn validate(token: &str, jwk: &Jwk, validations: Validations) -> Auth0Result<ValidJwt> {
    use crate::error::Error;
    use jsonwebtoken::{decode, jwk::AlgorithmParameters, DecodingKey};

    let jwt = match jwk.algorithm {
        AlgorithmParameters::RSA(ref rsa) => {
            let key =
                DecodingKey::from_rsa_components(&rsa.n, &rsa.e).map_err(|_| Error::InvalidJwk)?;
            decode::<Claims>(token, &key, &validations)?
        }
        _ => return Err(Error::InvalidJwk),
    };
    Ok(jwt)
}
#[cfg(feature = "alcoholic_jwt")]
pub use alcoholic_jwt::validate;

#[cfg(feature = "jsonwebtoken")]
pub fn get_kid(token: &str) -> Auth0Result<String> {
    let header = jsonwebtoken::decode_header(token)?;
    header.kid.ok_or(Error::JwtMissingKid)
}

#[cfg(feature = "alcoholic_jwt")]
pub fn get_kid(token: &str) -> Auth0Result<String> {
    match alcoholic_jwt::token_kid(token) {
        Ok(Some(res)) => Ok(res),
        _ => return Err(Error::JwtMissingKid),
    }
}

#[cfg(feature = "log")]
pub use log;
#[cfg(feature = "tracing")]
pub use tracing as log;

#[cfg(feature = "jsonwebtoken")]
pub fn complete_validations(domain: impl AsRef<str>, audience: impl AsRef<str>) -> Validations {
    use jsonwebtoken::{Algorithm, Validation};
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience.as_ref()]);
    validation.set_issuer(&[domain.as_ref()]);
    validation
}

#[cfg(feature = "alcoholic_jwt")]
pub fn complete_validations(domain: impl AsRef<str>, audience: impl AsRef<str>) -> Validations {
    pub use alcoholic_jwt::Validation;
    vec![
        Validation::NotExpired,
        Validation::Issuer(domain.as_ref().into()),
        Validation::Audience(audience.as_ref().into()),
    ]
}

#[cfg(feature = "jsonwebtoken")]
pub fn test_validations() -> Validations {
    use std::collections::HashSet;
    use jsonwebtoken::{Algorithm, Validation};
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims = HashSet::from_iter([String::from("sub")].into_iter());
    validation
}

#[cfg(feature = "alcoholic_jwt")]
pub fn test_validations() -> Validations {
    pub use alcoholic_jwt::Validation;
    vec![Validation::SubjectPresent]
}

lazy_static! {
    /// Regex to remove duplicate slashes from URLs
    pub static ref URL_REGEX: Regex = Regex::new(r"([^:]/)/+").expect("URL Regex error");
}
