use alloc::format;

use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha1::Sha1;

use super::error::CertError;
use super::parser::AttributeCertificate;

/// Verify the RSA-2048 + SHA-1 signature on an Attribute Certificate.
///
/// Returns `Ok(())` if valid. Err variants: `DerParse` if the signature bytes
/// are malformed, `SignatureInvalid` if the key doesn't match.
pub fn verify_signature(
    cert: &AttributeCertificate,
    issuer_pubkey: &RsaPublicKey,
) -> Result<(), CertError> {
    let verifying_key: VerifyingKey<Sha1> = VerifyingKey::new(issuer_pubkey.clone());

    let signature = Signature::try_from(cert.signature.as_slice())
        .map_err(|e| CertError::DerParse(format!("invalid signature bytes: {e}")))?;

    verifying_key
        .verify(&cert.tbs_bytes, &signature)
        .map_err(|_| CertError::SignatureInvalid)
}
