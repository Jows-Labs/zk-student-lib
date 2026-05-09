// Env vars (all optional, fall back to safe defaults):
//   MOCK_ISSUER_SK_DER  — base64 PKCS#1 DER private key for signing
//   MOCK_AIA_URL        — URL for the Authority Information Access extension

use rand::SeedableRng;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs1v15::SigningKey,
    signature::{SignatureEncoding, Signer},
    RsaPrivateKey, RsaPublicKey,
};
use sha1::{Digest, Sha1};

pub struct MockCert {
    pub der: Vec<u8>,
    pub issuer_pubkey: RsaPublicKey,
    pub issuer_privkey: RsaPrivateKey,
}

/// Fixed-width layout per Portaria ITI nº 68/2019 (CACIE v3.0) §2.8.
pub struct CertInput {
    // OID 2.16.76.1.10.1 — student identity
    pub birth_date: String,        // ddmmaaaa (8 chars)
    pub cpf:        String,        // 11 digits; "00000000000" when unavailable
    pub matricula:  String,        // up to 15 chars, zero-padded left
    pub rg:         String,        // up to 15 chars, zero-padded left
    pub rg_org_uf:  Option<String>,// up to 10 chars (issuing body + UF)

    // OID 2.16.76.1.10.2 — institution
    pub institution:  String,      // up to 40 chars
    pub degree:       String,      // up to 15 chars (e.g. "SUPERIOR")
    pub course:       String,      // up to 30 chars
    pub municipality: String,      // up to 20 chars
    pub uf:           String,      // 2 chars

    // OID 2.16.76.1.4.3 — nome social (Decreto 8.727/2016)
    pub social_name: Option<String>,

    pub issuer_cn:  String,
    pub not_before: String, // GeneralizedTime "YYYYMMDDHHMMSSZ"
    pub not_after:  String, // GeneralizedTime "YYYYMMDDHHMMSSZ"
    pub serial:     Vec<u8>,
}

impl Default for CertInput {
    fn default() -> Self {
        Self {
            birth_date:   "01012000".into(),
            cpf:          "12345678901".into(),
            matricula:    "0".into(),
            rg:           "523638395".into(),
            rg_org_uf:    None,
            institution:  "Federal University of Testing".into(),
            degree:       "SUPERIOR".into(),
            course:       "Computer Science".into(),
            municipality: "Sao Paulo".into(),
            uf:           "SP".into(),
            social_name:  None,
            issuer_cn:    "TEST STUDENT ENTITY".into(),
            not_before:   "20260101120000Z".into(),
            not_after:    "20270331235959Z".into(),
            serial:       vec![0x01, 0x10, 0x65, 0x36],
        }
    }
}

/// Deterministic RSA-2048 issuer key (seed = 42). Stable across builds.
pub fn mock_issuer_privkey() -> RsaPrivateKey {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    RsaPrivateKey::new(&mut rng, 2048).expect("seeded keygen cannot fail")
}

/// PKCS#1 DER bytes of the mock issuer public key, for circuit fixtures.
pub fn mock_issuer_pubkey_der() -> Vec<u8> {
    RsaPublicKey::from(&mock_issuer_privkey())
        .to_pkcs1_der()
        .expect("encoding cannot fail")
        .to_vec()
}

/// Base64 PKCS#1 DER of the seeded private key — paste into MOCK_ISSUER_SK_DER.
pub fn mock_issuer_sk_b64() -> String {
    let der = mock_issuer_privkey()
        .to_pkcs1_der()
        .expect("encoding cannot fail");
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der.as_bytes())
}

pub fn mock_cert() -> MockCert {
    mock_cert_from(&CertInput::default())
}

pub fn mock_cert_from(input: &CertInput) -> MockCert {
    let privkey = if let Ok(b64) = std::env::var("MOCK_ISSUER_SK_DER") {
        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
            .expect("MOCK_ISSUER_SK_DER: invalid base64");
        RsaPrivateKey::from_pkcs1_der(&der).expect("MOCK_ISSUER_SK_DER: invalid PKCS#1 DER")
    } else {
        mock_issuer_privkey()
    };
    let pubkey = RsaPublicKey::from(&privkey);

    let tbs = build_tbs(input, &pubkey);
    let sig = SigningKey::<Sha1>::new(privkey.clone()).sign(&tbs);
    let sig_bytes = sig.to_bytes();

    let cert_der = der_seq(&[tbs, sha1_rsa_algo(), der_bit_string(sig_bytes.as_ref())].concat());

    MockCert { der: cert_der, issuer_pubkey: pubkey, issuer_privkey: privkey }
}

fn build_tbs(input: &CertInput, pubkey: &RsaPublicKey) -> Vec<u8> {
    der_seq(
        &[
            der_integer(&[0x01]),           // version v2 encoded as integer 1 (zero-indexed)
            der_seq(&[]),                   // holder (empty; parser skips it)
            build_issuer(&input.issuer_cn),
            sha1_rsa_algo(),                // inner signature algorithm (required by spec)
            der_integer(&input.serial),
            der_seq(&[
                der_generalized_time(&input.not_before),
                der_generalized_time(&input.not_after),
            ].concat()),
            build_attributes(input),
            der_seq(&[build_aki(pubkey), build_aia()].concat()), // mandatory: AKI + AIA (§2.9)
        ]
        .concat(),
    )
}

fn build_issuer(cn: &str) -> Vec<u8> {
    let cn_attr = der_set(&der_seq(
        &[der_oid(&[0x55, 0x04, 0x03]), der_utf8_string(cn)].concat(),
    ));
    der_tag(0xA0, &der_seq(&cn_attr))
}

fn build_attributes(input: &CertInput) -> Vec<u8> {
    let identity = der_seq(
        &[
            der_oid(&[0x60, 0x4C, 0x01, 0x0A, 0x01]),
            der_set(&der_printable_string(&identity_string(input))),
        ]
        .concat(),
    );
    let institution = der_seq(
        &[
            der_oid(&[0x60, 0x4C, 0x01, 0x0A, 0x02]),
            der_set(&der_printable_string(&institution_string(input))),
        ]
        .concat(),
    );
    let social_val = input.social_name.as_deref().unwrap_or("");
    let social_name = der_seq(
        &[
            der_oid(&[0x60, 0x4C, 0x01, 0x04, 0x03]),
            der_set(&der_printable_string(social_val)),
        ]
        .concat(),
    );
    der_seq(&[identity, institution, social_name].concat())
}

fn build_aki(pubkey: &RsaPublicKey) -> Vec<u8> {
    let pub_der = pubkey.to_pkcs1_der().unwrap();
    let key_id: [u8; 20] = Sha1::digest(pub_der.as_ref()).into();
    let aki_val = der_seq(&der_tag(0x80, &key_id));
    der_seq(&[der_oid(&[0x55, 0x1D, 0x23]), der_octet_string(&aki_val)].concat())
}

fn build_aia() -> Vec<u8> {
    let url =
        std::env::var("MOCK_AIA_URL").unwrap_or_else(|_| "http://test.example.com/ca.crt".into());
    let access_desc = der_seq(
        &[
            der_oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02]),
            der_tag(0x86, url.as_bytes()), // [6] IA5String URI
        ]
        .concat(),
    );
    der_seq(
        &[
            der_oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]),
            der_octet_string(&der_seq(&access_desc)),
        ]
        .concat(),
    )
}

/// OID 2.16.76.1.10.1 — 59 chars total
/// [00..08] birth date ddmmaaaa
/// [08..19] CPF (11 chars)
/// [19..34] matrícula (15 chars, zero-padded left)
/// [34..49] RG (15 chars, zero-padded left)
/// [49..59] RG issuing body + UF (10 chars, space-padded right; empty when RG absent)
fn identity_string(input: &CertInput) -> String {
    let org_uf = input.rg_org_uf.as_deref().unwrap_or("");
    format!(
        "{:<8.8}{:<11.11}{:0>15.15}{:0>15.15}{:<10.10}",
        input.birth_date, input.cpf, input.matricula, input.rg, org_uf,
    )
}

/// OID 2.16.76.1.10.2 — 107 chars total
/// [000..040] institution name (40 chars)
/// [040..055] degree level (15 chars)
/// [055..085] course (30 chars)
/// [085..105] municipality (20 chars)
/// [105..107] UF (2 chars)
fn institution_string(input: &CertInput) -> String {
    format!(
        "{:<40.40}{:<15.15}{:<30.30}{:<20.20}{:<2.2}",
        input.institution, input.degree, input.course, input.municipality, input.uf,
    )
}

fn sha1_rsa_algo() -> Vec<u8> {
    // OID 1.2.840.113549.1.1.5 (sha1WithRSAEncryption) + NULL
    der_seq(
        &[
            der_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05]),
            vec![0x05, 0x00],
        ]
        .concat(),
    )
}

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

fn der_seq(content: &[u8]) -> Vec<u8>        { der_tag(0x30, content) }
fn der_set(content: &[u8]) -> Vec<u8>        { der_tag(0x31, content) }
fn der_oid(bytes: &[u8]) -> Vec<u8>          { der_tag(0x06, bytes) }
fn der_integer(bytes: &[u8]) -> Vec<u8>      { der_tag(0x02, bytes) }
fn der_octet_string(bytes: &[u8]) -> Vec<u8> { der_tag(0x04, bytes) }
fn der_utf8_string(s: &str) -> Vec<u8>       { der_tag(0x0C, s.as_bytes()) }
fn der_printable_string(s: &str) -> Vec<u8>  { der_tag(0x13, s.as_bytes()) }
fn der_generalized_time(s: &str) -> Vec<u8>  { der_tag(0x18, s.as_bytes()) }

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00]; // unused-bits count (always 0 for RSA)
    content.extend_from_slice(bytes);
    der_tag(0x03, &content)
}
