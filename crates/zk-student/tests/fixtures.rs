// Generates a synthetic DNE-like Attribute Certificate for testing.
// No stored bytes — cert and key pair are built fresh on each call.
//
// Birth date:  2000-01-01
// Issuer CN:   "ENTIDADE TESTE DE ESTUDANTES"
// Valid:       2026-01-01 → 2027-03-31

use rand::SeedableRng;
use rsa::{
    pkcs1v15::SigningKey,
    signature::{SignatureEncoding, Signer},
    RsaPrivateKey, RsaPublicKey,
};
use sha1::Sha1;

pub struct TestCert {
    pub der: Vec<u8>,
    pub issuer_pubkey: RsaPublicKey,
}

pub fn generate() -> TestCert {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let privkey = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pubkey = RsaPublicKey::from(&privkey);

    let tbs = build_tbs();
    let sig = SigningKey::<Sha1>::new(privkey).sign(&tbs);
    let sig_bytes = sig.to_bytes();

    let cert_der = der_seq(&[tbs, sha1_rsa_algo(), der_bit_string(sig_bytes.as_ref())].concat());

    TestCert { der: cert_der, issuer_pubkey: pubkey }
}

// ── Certificate structure ────────────────────────────────────────────────────

fn build_tbs() -> Vec<u8> {
    der_seq(&[
        der_integer(&[0x01]),       // version
        der_seq(&[]),               // holder (parser skips it)
        build_issuer(),
        sha1_rsa_algo(),            // inner sig algo
        der_integer(&[0x01, 0x10, 0x65, 0x36]), // serial
        build_validity(),
        build_attributes(),
    ].concat())
}

fn build_issuer() -> Vec<u8> {
    // [0] { SEQUENCE { SET { SEQUENCE { OID CN, value } } } }
    // The parser recursively searches for OID 2.5.4.3 — nesting depth doesn't matter.
    let cn = der_set(&der_seq(&[
        der_oid(&[0x55, 0x04, 0x03]),
        der_utf8_string("ENTIDADE TESTE DE ESTUDANTES"),
    ].concat()));
    der_tag(0xA0, &der_seq(&cn))
}

fn build_validity() -> Vec<u8> {
    der_seq(&[
        der_generalized_time("20260101120000Z"),
        der_generalized_time("20270331235959Z"),
    ].concat())
}

fn build_attributes() -> Vec<u8> {
    // OID 2.16.76.1.10.1 — student identity, first 8 chars = birth date DDMMYYYY
    let identity = der_seq(&[
        der_oid(&[0x60, 0x4C, 0x01, 0x0A, 0x01]),
        der_set(&der_printable_string(
            "01012000123456789010000000000000000000000523638395          ",
        )),
    ].concat());

    // OID 2.16.76.1.10.2 — institution data
    let institution = der_seq(&[
        der_oid(&[0x60, 0x4C, 0x01, 0x0A, 0x02]),
        der_set(&der_printable_string(
            "Universidade Federal de Teste           SUPERIOR       Ciencia da Computacao         Sao Paulo             SP",
        )),
    ].concat());

    // OID 2.16.76.1.4.3 — CPF (empty)
    let cpf = der_seq(&[
        der_oid(&[0x60, 0x4C, 0x01, 0x04, 0x03]),
        der_set(&der_printable_string("")),
    ].concat());

    der_seq(&[identity, institution, cpf].concat())
}

fn sha1_rsa_algo() -> Vec<u8> {
    // OID 1.2.840.113549.1.1.5 (sha1WithRSAEncryption) + NULL
    der_seq(&[
        der_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05]),
        vec![0x05, 0x00],
    ].concat())
}

// ── DER primitives ───────────────────────────────────────────────────────────

fn der_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n <= 0xFF {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, n as u8]
    }
}

fn der_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_seq(content: &[u8]) -> Vec<u8>            { der_tag(0x30, content) }
fn der_set(content: &[u8]) -> Vec<u8>            { der_tag(0x31, content) }
fn der_oid(bytes: &[u8]) -> Vec<u8>              { der_tag(0x06, bytes) }
fn der_integer(bytes: &[u8]) -> Vec<u8>          { der_tag(0x02, bytes) }
fn der_utf8_string(s: &str) -> Vec<u8>           { der_tag(0x0C, s.as_bytes()) }
fn der_printable_string(s: &str) -> Vec<u8>      { der_tag(0x13, s.as_bytes()) }
fn der_generalized_time(s: &str) -> Vec<u8>      { der_tag(0x18, s.as_bytes()) }

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00]; // 0 padding bits
    content.extend_from_slice(bytes);
    der_tag(0x03, &content)
}
