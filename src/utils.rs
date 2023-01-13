use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// Regex to remove duplicate slashes from URLs
    pub static ref URL_REGEX: Regex = Regex::new(r"([^:]/)/+").expect("URL Regex error");
}
