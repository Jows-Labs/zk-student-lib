use alloc::string::String;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertError {
    #[error("failed to decode PEM: {0}")]
    PemDecode(String),

    #[error("failed to parse DER: {0}")]
    DerParse(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("invalid date format: {0}")]
    InvalidDate(String),

    #[error("signature verification failed")]
    SignatureInvalid,
}
