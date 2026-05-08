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

println!("{}", cert.fields.birth_date);  // 2005-12-12
println!("{}", cert.fields.not_after);   // 2027-03-31
println!("{}", cert.fields.issuer_cn);   // UNIAO NACIONAL DOS ESTUDANTES

let is_valid = verify_signature(&cert, &issuer_pubkey).unwrap();
```

## License

MIT
