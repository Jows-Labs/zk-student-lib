use super::error::CertError;
use time::Date;
use time::Month;

/// Extracted fields from a DNE/CIE Attribute Certificate.
#[derive(Debug, Clone)]
pub struct CertFields {
    /// Holder's birth date (from OID 2.16.76.1.10.1).
    pub birth_date: Date,
    /// Certificate validity start.
    pub not_before: Date,
    /// Certificate validity end.
    pub not_after: Date,
    /// Issuer common name.
    pub issuer_cn: String,
    /// Raw TBS (to-be-signed) bytes for signature verification.
    pub tbs_bytes: Vec<u8>,
    /// The RSA signature bytes.
    pub signature: Vec<u8>,
}

// ASN.1 DER tag constants
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OID: u8 = 0x06;
const TAG_UTF8STRING: u8 = 0x0C;
const TAG_PRINTABLESTRING: u8 = 0x13;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_CONTEXT_0: u8 = 0xA0;

/// OID for student identity data (birth date, document numbers).
/// 2.16.76.1.10.1 encoded as DER bytes.
const OID_STUDENT_IDENTITY: &[u8] = &[0x60, 0x4C, 0x01, 0x0A, 0x01];


/// A parsed DNE/CIE Attribute Certificate.
#[derive(Debug, Clone)]
pub struct AttributeCertificate {
    /// The raw DER bytes of the full certificate.
    pub raw_der: Vec<u8>,
    /// Extracted fields.
    pub fields: CertFields,
}

/// Parse a PEM-encoded Attribute Certificate.
pub fn parse_pem(pem: &str) -> Result<AttributeCertificate, CertError> {
    let der_bytes = pem_to_der(pem)?;
    parse_der(&der_bytes)
}

/// Parse a DER-encoded Attribute Certificate.
///
/// Walks the ASN.1 structure properly (no hardcoded offsets) to extract:
/// - TBS bytes and RSA signature (for verification)
/// - Birth date from OID 2.16.76.1.10.1
/// - Validity period (notBefore, notAfter)
/// - Issuer common name
pub fn parse_der(der_bytes: &[u8]) -> Result<AttributeCertificate, CertError> {
    // Outer SEQUENCE: { TBS, signatureAlgorithm, signatureValue }
    let outer = read_tlv(der_bytes, 0)?;
    expect_tag(TAG_SEQUENCE, outer.tag)?;

    let mut pos = outer.content_offset;

    // 1. TBS SEQUENCE (includes the tag+length header — this is what gets signed)
    let tbs_tlv = read_tlv(der_bytes, pos)?;
    expect_tag(TAG_SEQUENCE, tbs_tlv.tag)?;
    let tbs_bytes = der_bytes[tbs_tlv.element_start..tbs_tlv.element_end()].to_vec();
    pos = tbs_tlv.element_end();

    // 2. Signature Algorithm SEQUENCE (skip it)
    let sig_algo_tlv = read_tlv(der_bytes, pos)?;
    expect_tag(TAG_SEQUENCE, sig_algo_tlv.tag)?;
    pos = sig_algo_tlv.element_end();

    // 3. Signature BIT STRING
    let sig_tlv = read_tlv(der_bytes, pos)?;
    expect_tag(TAG_BIT_STRING, sig_tlv.tag)?;
    // BIT STRING content: first byte is padding bits count (0 for RSA), rest is signature
    let sig_content = &der_bytes[sig_tlv.content_offset..sig_tlv.element_end()];
    if sig_content.is_empty() {
        return Err(CertError::DerParse("empty signature".into()));
    }
    let signature = sig_content[1..].to_vec(); // skip padding byte

    // Now parse inside TBS to extract fields
    let fields = parse_tbs(&tbs_bytes, signature)?;

    Ok(AttributeCertificate {
        raw_der: der_bytes.to_vec(),
        fields,
    })
}

/// Parse the TBS (To-Be-Signed) portion of the Attribute Certificate.
fn parse_tbs(tbs_bytes: &[u8], signature: Vec<u8>) -> Result<CertFields, CertError> {
    let tbs_seq = read_tlv(tbs_bytes, 0)?;
    let mut pos = tbs_seq.content_offset;
    // version INTEGER
    let version_tlv = read_tlv(tbs_bytes, pos)?;
    expect_tag(TAG_INTEGER, version_tlv.tag)?;
    pos = version_tlv.element_end();

    // holder SEQUENCE
    let holder_tlv = read_tlv(tbs_bytes, pos)?;
    expect_tag(TAG_SEQUENCE, holder_tlv.tag)?;
    pos = holder_tlv.element_end();

    // issuer [0] (context-specific, constructed)
    let issuer_tlv = read_tlv(tbs_bytes, pos)?;
    expect_tag(TAG_CONTEXT_0, issuer_tlv.tag)?;
    let issuer_cn = extract_common_name(tbs_bytes, issuer_tlv.content_offset, issuer_tlv.element_end())?;
    pos = issuer_tlv.element_end();

    // signature algorithm SEQUENCE (inside TBS — skip)
    let inner_sig_algo = read_tlv(tbs_bytes, pos)?;
    expect_tag(TAG_SEQUENCE, inner_sig_algo.tag)?;
    pos = inner_sig_algo.element_end();

    // serial number INTEGER (skip)
    let serial_tlv = read_tlv(tbs_bytes, pos)?;
    expect_tag(TAG_INTEGER, serial_tlv.tag)?;
    pos = serial_tlv.element_end();

    // validity period SEQUENCE { notBefore, notAfter }
    let validity_tlv = read_tlv(tbs_bytes, pos)?;
    expect_tag(TAG_SEQUENCE, validity_tlv.tag)?;

    let not_before_tlv = read_tlv(tbs_bytes, validity_tlv.content_offset)?;
    expect_tag(TAG_GENERALIZED_TIME, not_before_tlv.tag)?;
    let not_before = parse_generalized_time(
        &tbs_bytes[not_before_tlv.content_offset..not_before_tlv.element_end()],
    )?;

    let not_after_tlv = read_tlv(tbs_bytes, not_before_tlv.element_end())?;
    expect_tag(TAG_GENERALIZED_TIME, not_after_tlv.tag)?;
    let not_after = parse_generalized_time(
        &tbs_bytes[not_after_tlv.content_offset..not_after_tlv.element_end()],
    )?;

    pos = validity_tlv.element_end();

    // attributes SEQUENCE OF Attribute
    let attrs_tlv = read_tlv(tbs_bytes, pos)?;
    expect_tag(TAG_SEQUENCE, attrs_tlv.tag)?;

    let birth_date = find_attribute_string(
        tbs_bytes,
        attrs_tlv.content_offset,
        attrs_tlv.element_end(),
        OID_STUDENT_IDENTITY,
    )?
    .ok_or(CertError::MissingField("birth date (OID 2.16.76.1.10.1)"))?;

    let birth_date = parse_birth_date(&birth_date)?;

    Ok(CertFields {
        birth_date,
        not_before,
        not_after,
        issuer_cn,
        tbs_bytes: tbs_bytes.to_vec(),
        signature,
    })
}

/// Find an attribute by OID and return its PRINTABLESTRING value.
fn find_attribute_string(
    data: &[u8],
    start: usize,
    end: usize,
    target_oid: &[u8],
) -> Result<Option<String>, CertError> {
    let mut pos = start;
    while pos < end {
        let attr_seq = read_tlv(data, pos)?;
        if attr_seq.tag != TAG_SEQUENCE {
            pos = attr_seq.element_end();
            continue;
        }

        // Each attribute: SEQUENCE { OID, SET { value } }
        let oid_tlv = read_tlv(data, attr_seq.content_offset)?;
        if oid_tlv.tag == TAG_OID {
            let oid_bytes = &data[oid_tlv.content_offset..oid_tlv.element_end()];
            if oid_bytes == target_oid {
                // Found it — read the SET, then the PRINTABLESTRING inside
                let set_tlv = read_tlv(data, oid_tlv.element_end())?;
                if set_tlv.tag == TAG_SET {
                    let val_tlv = read_tlv(data, set_tlv.content_offset)?;
                    if val_tlv.tag == TAG_PRINTABLESTRING || val_tlv.tag == TAG_UTF8STRING {
                        let val = &data[val_tlv.content_offset..val_tlv.element_end()];
                        let s = core::str::from_utf8(val)
                            .map_err(|e| CertError::DerParse(e.to_string()))?;
                        return Ok(Some(s.to_string()));
                    }
                }
            }
        }

        pos = attr_seq.element_end();
    }
    Ok(None)
}

/// Extract the commonName (CN) from a DN structure.
fn extract_common_name(data: &[u8], start: usize, end: usize) -> Result<String, CertError> {
    // CN OID: 2.5.4.3
    const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

    // Walk through nested structures to find the DN SEQUENCEs
    let cn = find_oid_value_recursive(data, start, end, OID_CN)?;
    cn.ok_or(CertError::MissingField("issuer commonName"))
}

/// Recursively search for an OID and return the string value that follows it.
fn find_oid_value_recursive(
    data: &[u8],
    start: usize,
    end: usize,
    target_oid: &[u8],
) -> Result<Option<String>, CertError> {
    let mut pos = start;
    while pos < end {
        let tlv = read_tlv(data, pos)?;

        if tlv.tag == TAG_OID {
            let oid_bytes = &data[tlv.content_offset..tlv.element_end()];
            if oid_bytes == target_oid {
                // The value follows the OID in the same SEQUENCE
                let val_tlv = read_tlv(data, tlv.element_end())?;
                if val_tlv.tag == TAG_UTF8STRING
                    || val_tlv.tag == TAG_PRINTABLESTRING
                {
                    let val = &data[val_tlv.content_offset..val_tlv.element_end()];
                    let s = core::str::from_utf8(val)
                        .map_err(|e| CertError::DerParse(e.to_string()))?;
                    return Ok(Some(s.to_string()));
                }
            }
        }

        // If this is a constructed type, search inside it
        if is_constructed(tlv.tag) {
            if let Some(found) =
                find_oid_value_recursive(data, tlv.content_offset, tlv.element_end(), target_oid)?
            {
                return Ok(Some(found));
            }
        }

        pos = tlv.element_end();
    }
    Ok(None)
}

/// Parse birth date from OID 2.16.76.1.10.1 value string.
/// Format: "DDMMYYYY..." (first 8 chars).
fn parse_birth_date(raw: &str) -> Result<Date, CertError> {
    if raw.len() < 8 {
        return Err(CertError::InvalidDate(format!(
            "identity field too short: '{raw}'"
        )));
    }
    let dd: u8 = raw[0..2]
        .parse()
        .map_err(|_| CertError::InvalidDate(format!("bad day: '{}'", &raw[0..2])))?;
    let mm: u8 = raw[2..4]
        .parse()
        .map_err(|_| CertError::InvalidDate(format!("bad month: '{}'", &raw[2..4])))?;
    let yyyy: i32 = raw[4..8]
        .parse()
        .map_err(|_| CertError::InvalidDate(format!("bad year: '{}'", &raw[4..8])))?;

    let month = Month::try_from(mm)
        .map_err(|_| CertError::InvalidDate(format!("invalid month: {mm}")))?;
    Date::from_calendar_date(yyyy, month, dd)
        .map_err(|_| CertError::InvalidDate(format!("invalid date: {dd}/{mm}/{yyyy}")))
}

/// Parse GeneralizedTime "YYYYMMDDHHMMSSZ" into Date.
fn parse_generalized_time(bytes: &[u8]) -> Result<Date, CertError> {
    let s = core::str::from_utf8(bytes)
        .map_err(|e| CertError::InvalidDate(e.to_string()))?;
    if s.len() < 8 {
        return Err(CertError::InvalidDate(format!(
            "GeneralizedTime too short: '{s}'"
        )));
    }
    let yyyy: i32 = s[0..4]
        .parse()
        .map_err(|_| CertError::InvalidDate(format!("bad year: '{}'", &s[0..4])))?;
    let mm: u8 = s[4..6]
        .parse()
        .map_err(|_| CertError::InvalidDate(format!("bad month: '{}'", &s[4..6])))?;
    let dd: u8 = s[6..8]
        .parse()
        .map_err(|_| CertError::InvalidDate(format!("bad day: '{}'", &s[6..8])))?;

    let month = Month::try_from(mm)
        .map_err(|_| CertError::InvalidDate(format!("invalid month: {mm}")))?;
    Date::from_calendar_date(yyyy, month, dd)
        .map_err(|_| CertError::InvalidDate(format!("invalid date: {yyyy}-{mm}-{dd}")))
}

// ──── Low-level DER TLV reader ────

/// A parsed DER Tag-Length-Value element.
#[derive(Debug, Clone, Copy)]
struct Tlv {
    /// The ASN.1 tag byte.
    tag: u8,
    /// Byte offset where the full element starts (the tag byte).
    element_start: usize,
    /// Byte offset where the content (value) starts (after tag + length).
    content_offset: usize,
    /// Length of the content in bytes.
    content_length: usize,
}

impl Tlv {
    /// Byte offset where the full element ends.
    fn element_end(&self) -> usize {
        self.content_offset + self.content_length
    }
}

/// Read a DER TLV element at the given offset.
fn read_tlv(data: &[u8], offset: usize) -> Result<Tlv, CertError> {
    if offset >= data.len() {
        return Err(CertError::DerParse(format!(
            "offset {offset} past end of data (len {})",
            data.len()
        )));
    }

    let tag = data[offset];
    let (content_length, header_size) = read_der_length(data, offset + 1)?;

    Ok(Tlv {
        tag,
        element_start: offset,
        content_offset: offset + 1 + header_size,
        content_length,
    })
}

/// Read a DER length encoding starting at `offset`.
/// Returns (length, number of bytes consumed by the length encoding).
fn read_der_length(data: &[u8], offset: usize) -> Result<(usize, usize), CertError> {
    if offset >= data.len() {
        return Err(CertError::DerParse("unexpected end of data reading length".into()));
    }

    let first = data[offset];

    if first < 0x80 {
        // Short form: length is the byte itself
        Ok((first as usize, 1))
    } else if first == 0x80 {
        Err(CertError::DerParse("indefinite length not supported in DER".into()))
    } else {
        // Long form: first byte = 0x80 | num_bytes
        let num_bytes = (first & 0x7F) as usize;
        if offset + 1 + num_bytes > data.len() {
            return Err(CertError::DerParse("length encoding extends past data".into()));
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | (data[offset + 1 + i] as usize);
        }
        Ok((length, 1 + num_bytes))
    }
}

/// Check if a tag represents a constructed (container) type.
fn is_constructed(tag: u8) -> bool {
    tag & 0x20 != 0
}

/// Assert that the tag matches what we expect.
fn expect_tag(expected: u8, actual: u8) -> Result<(), CertError> {
    if actual != expected {
        Err(CertError::DerParse(format!(
            "expected tag 0x{expected:02X}, got 0x{actual:02X}"
        )))
    } else {
        Ok(())
    }
}

/// Decode PEM to DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, CertError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    STANDARD.decode(&b64).map_err(|e| CertError::PemDecode(e.to_string()))
}

