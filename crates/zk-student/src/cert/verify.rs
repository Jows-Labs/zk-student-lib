use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha1::Sha1;

use super::error::CertError;
use super::parser::AttributeCertificate;

/// Verify the RSA-2048 + SHA-1 signature on an Attribute Certificate.
///
/// The `issuer_pubkey` is the RSA public key of the entity that signed
/// the certificate (e.g., UNE for DNE certificates).
pub fn verify_signature(
    cert: &AttributeCertificate,
    issuer_pubkey: &RsaPublicKey,
) -> Result<bool, CertError> {
    let verifying_key: VerifyingKey<Sha1> = VerifyingKey::new(issuer_pubkey.clone());

    let signature = Signature::try_from(cert.fields.signature.as_slice())
        .map_err(|e| CertError::DerParse(format!("invalid signature bytes: {e}")))?;

    Ok(verifying_key
        .verify(&cert.fields.tbs_bytes, &signature)
        .is_ok())
}
