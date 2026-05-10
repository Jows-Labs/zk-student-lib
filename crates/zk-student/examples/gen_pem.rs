use base64::{engine::general_purpose::STANDARD, Engine};
use rsa::pkcs1::EncodeRsaPublicKey;
use zk_student::cert::{parse_der, verify_signature};
use zk_student::mock::{mock_cert_from, CertInput};

fn pem_wrap(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let lines = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n")
}

fn main() {
    let cert = mock_cert_from(&CertInput {
        social_name: Some("JOHN DOE".into()),
        ..CertInput::default()
    });

    let cert_pem = pem_wrap("CERTIFICATE", &cert.der);
    let pubkey_der = cert
        .issuer_pubkey
        .to_pkcs1_der()
        .expect("pubkey encoding failed");
    let pubkey_pem = pem_wrap("RSA PUBLIC KEY", pubkey_der.as_bytes());

    std::fs::write("mock_cert.pem", &cert_pem).expect("write failed");
    std::fs::write("mock_issuer_pubkey.pem", &pubkey_pem).expect("write failed");
    println!("Written to mock_cert.pem and mock_issuer_pubkey.pem\n");
    print!("{cert_pem}");
    print!("{pubkey_pem}");

    let parsed = parse_der(&cert.der).expect("parse failed");
    match verify_signature(&parsed, &cert.issuer_pubkey) {
        Ok(()) => println!("Signature OK"),
        Err(e) => eprintln!("Signature FAILED: {e}"),
    }
}
