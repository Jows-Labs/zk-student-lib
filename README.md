# zk-student-lib

Parses and verifies Brazilian DNE/CIE student identity certificates (X.509 Attribute Certificates, RSA-2048 + SHA-1).

## What it does

- Parse PEM and DER certificates
- Extract birth date, validity period, and issuer CN
- Verify the RSA signature against the issuer's public key

## Usage

```toml
[dependencies]
zk-student = { git = "https://github.com/Jows-Labs/zk-student-lib" }
```

```rust
use zk_student::cert::{parse_pem, verify_signature};

let pem = std::fs::read_to_string("student.pem").unwrap();
let cert = parse_pem(&pem).unwrap();

// time::Date fields — access components directly or enable the `time/formatting` feature to Display them
let f = &cert.fields;
println!("{}-{}-{}", f.birth_date.year(), f.birth_date.month(), f.birth_date.day());
println!("{}", f.issuer_cn); // UNIAO NACIONAL DOS ESTUDANTES

verify_signature(&cert, &issuer_pubkey)?; // Err(SignatureInvalid) if key doesn't match
```

## License

MIT
