use rsa::pkcs1::DecodeRsaPublicKey;
use serde::Serialize;
use wasm_bindgen::prelude::*;
use zk_student::cert::{parse_der, verify_signature};

#[derive(Serialize)]
pub struct CertFields {
    pub birth_date: String, // "YYYY-MM-DD"
    pub not_before: String, // "YYYY-MM-DD"
    pub not_after: String,  // "YYYY-MM-DD"
    pub issuer_cn: String,
}

/// Parse a DER-encoded attribute certificate and return its fields.
#[wasm_bindgen]
pub fn parse_cert(der: &[u8]) -> Result<JsValue, JsError> {
    let cert = parse_der(der).map_err(|e| JsError::new(&e.to_string()))?;
    let f = &cert.fields;
    let fields = CertFields {
        birth_date: format!(
            "{}-{:02}-{:02}",
            f.birth_date.year(),
            f.birth_date.month() as u8,
            f.birth_date.day()
        ),
        not_before: format!(
            "{}-{:02}-{:02}",
            f.not_before.year(),
            f.not_before.month() as u8,
            f.not_before.day()
        ),
        not_after: format!(
            "{}-{:02}-{:02}",
            f.not_after.year(),
            f.not_after.month() as u8,
            f.not_after.day()
        ),
        issuer_cn: f.issuer_cn.clone(),
    };
    Ok(serde_wasm_bindgen::to_value(&fields)?)
}

/// Verify the RSA signature. Throws if the certificate or key is invalid,
/// or if the signature does not match.
#[wasm_bindgen]
pub fn verify_cert(der: &[u8], issuer_pubkey_der: &[u8]) -> Result<(), JsError> {
    let cert = parse_der(der).map_err(|e| JsError::new(&e.to_string()))?;
    let pubkey = rsa::RsaPublicKey::from_pkcs1_der(issuer_pubkey_der)
        .map_err(|e| JsError::new(&e.to_string()))?;
    verify_signature(&cert, &pubkey).map_err(|e| JsError::new(&e.to_string()))
}
