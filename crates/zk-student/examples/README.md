# Examples

## gen_pem

Generates a mock CACIE cert for `JOHN DOE`, verifies the signature, and writes:

- `mock_cert.pem`
- `mock_issuer_pubkey.pem`

```sh
# default (seed-42 key)
cargo run --example gen_pem --features mock

# with .env key
MOCK_ISSUER_SK_DER="$(grep MOCK_ISSUER_SK_DER .env | cut -d= -f2-)" \
MOCK_AIA_URL="$(grep MOCK_AIA_URL .env | cut -d= -f2-)" \
  cargo run --example gen_pem --features mock
```

### CertInput examples

```rust
// minimal
CertInput { social_name: Some("JOHN DOE".into()), ..CertInput::default() }

// full
CertInput {
    social_name: Some("JANE DOE".into()),
    birth_date: "15031998".into(),
    cpf: "98765432100".into(),
    matricula: "20240012345".into(),
    rg: "123456789".into(),
    rg_org_uf: Some("SSPSP".into()),
    institution: "Universidade de Sao Paulo".into(),
    degree: "SUPERIOR".into(),
    course: "Engenharia de Software".into(),
    municipality: "Sao Paulo".into(),
    uf: "SP".into(),
    issuer_cn: "AC EDUCACIONAL MOCK".into(),
    not_before: "20260101000000Z".into(),
    not_after:  "20270101000000Z".into(),
    serial: vec![0x01, 0x02, 0x03, 0x04],
}

// no RG / CPF unavailable
CertInput { social_name: Some("RICHARD ROE".into()), cpf: "00000000000".into(), rg: "0".into(), rg_org_uf: None, ..CertInput::default() }

// expired
CertInput { not_before: "20230101000000Z".into(), not_after: "20240101000000Z".into(), ..CertInput::default() }
```

### Issuer public key constant (WASM / JS)

Matches the key in `.env`. Regenerate if you rotate `MOCK_ISSUER_SK_DER`.

```ts
const ISSUER_PUBKEY_DER = Uint8Array.from(atob(
  "MIIBCgKCAQEAxhjzPuiVgdtixl8xR5a657fiQ4WZXJChsoglEZqL96ovP+lo7Fix" +
  "EmyNLR3LfNA7mbCcFrYfi9arI5iShV9vSA8xvvdeqWXvUDT1CNCoOkbH8wpfNTwr" +
  "OijKhszPvj2fqLdJji2VrRJf7Vilj8yQ5KtweTAW4+BcLy5WkOa73lxbIPyzhlOJ" +
  "4Lwbl18uW7tlWBaQonySO4HDDFL3SO9NVFvxebD9g13kpw5M7PCgPQje02ebcgTi" +
  "88ZLlOhDdYYKkyGbVKK2kUMd9RTE4kn4r3suWmaxoCd0+17wJYYxrOflZ2dL+WRH" +
  "G7CMa4pYKEWxpLXo4bDsjcr4Frh+Y7//DQIDAQAB"
), c => c.charCodeAt(0));
```
