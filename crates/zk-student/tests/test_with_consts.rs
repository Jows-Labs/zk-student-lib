mod fixtures;

use time::{Date, Month};
use zk_student::cert::{parse_der, verify_signature};

#[test]
fn parses_birth_date() {
    let f = fixtures::generate();
    let cert = parse_der(&f.der).unwrap();
    assert_eq!(
        cert.fields.birth_date,
        Date::from_calendar_date(2000, Month::January, 1).unwrap()
    );
}

#[test]
fn parses_validity() {
    let f = fixtures::generate();
    let cert = parse_der(&f.der).unwrap();
    assert_eq!(
        cert.fields.not_before,
        Date::from_calendar_date(2026, Month::January, 1).unwrap()
    );
    assert_eq!(
        cert.fields.not_after,
        Date::from_calendar_date(2027, Month::March, 31).unwrap()
    );
}

#[test]
fn parses_issuer_cn() {
    let f = fixtures::generate();
    let cert = parse_der(&f.der).unwrap();
    assert_eq!(cert.fields.issuer_cn, "TEST STUDENT ENTITY");
}

#[test]
fn parses_signature_length() {
    let f = fixtures::generate();
    let cert = parse_der(&f.der).unwrap();
    assert_eq!(cert.signature.len(), 256);
}

#[test]
fn tbs_starts_with_sequence_tag() {
    let f = fixtures::generate();
    let cert = parse_der(&f.der).unwrap();
    assert_eq!(cert.tbs_bytes[0], 0x30);
}

#[test]
fn valid_signature_accepted() {
    let f = fixtures::generate();
    let cert = parse_der(&f.der).unwrap();
    assert!(verify_signature(&cert, &f.issuer_pubkey).is_ok());
}

#[test]
fn wrong_key_rejected() {
    let f = fixtures::generate();
    let cert = parse_der(&f.der).unwrap();
    let wrong_key =
        rsa::RsaPublicKey::from(&rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap());
    assert!(verify_signature(&cert, &wrong_key).is_err());
}

#[test]
fn tampered_cert_rejected() {
    let f = fixtures::generate();
    let mut tampered = f.der.clone();
    let n = tampered.len();
    tampered[n - 10] ^= 0xFF;
    let cert = parse_der(&tampered).unwrap();
    assert!(verify_signature(&cert, &f.issuer_pubkey).is_err());
}
