//! The console's TLS material: the auto-generated CA and server certificate, and the
//! minimal DER reading used to decide when an existing certificate must be renewed.

use super::*;

/// 397 days: the maximum a public CA (and therefore every browser) will accept for a
/// server certificate. A long-lived auto-generated key is a credential nobody rotates.
pub(super) const AUTOGEN_CERT_VALID_DAYS: i64 = 397;
// The 20-year original meant a leaked key stayed useful for the life of the machine.
const _: () = assert!(AUTOGEN_CERT_VALID_DAYS <= 397);

/// CN of the CA processmaster generates for itself. Doubles as the marker that tells an
/// expired certificate of ours apart from an operator's own.
pub(super) const AUTOGEN_CA_COMMON_NAME: &str = "processmaster-ca";

/// The host's name, if it is usable as a certificate DNS SAN.
///
/// Read from /proc rather than gethostname(2): this daemon is Linux/cgroup-v2 only, so
/// /proc is always mounted, and it keeps an unsafe call out of the TLS path. Anything
/// that is not a plain DNS label is rejected rather than fed to rcgen.
pub(super) fn system_hostname() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname").ok()?;
    let t = raw.trim().to_ascii_lowercase();
    if t.is_empty() || t.len() > 253 {
        return None;
    }
    if !t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return None;
    }
    Some(t)
}

/// Subject CN for the generated leaf. `CN=test` said nothing about which machine was
/// being talked to, which matters when several hosts each generate their own.
pub(super) fn autogen_cert_common_name(hostname: Option<&str>) -> String {
    hostname
        .map(|h| h.to_string())
        .unwrap_or_else(|| "processmaster".to_string())
}

/// SANs for the generated leaf, normalized (DNS lowercased, both sets deduped/sorted).
///
/// Modern clients ignore the CN entirely and match on SANs alone, so anything an
/// operator might type into the address bar has to be listed here: loopback, the host's
/// own name, the configured `client_host`, and the address the console actually binds.
/// A wildcard bind (0.0.0.0 / ::) names no particular interface and is skipped -- there
/// is nothing to put in the certificate.
pub(super) fn autogen_cert_sans(
    client_host: Option<&str>,
    bind_ip: IpAddr,
    hostname: Option<&str>,
) -> (Vec<String>, Vec<IpAddr>) {
    let mut dns_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut ip_set: std::collections::BTreeSet<IpAddr> = std::collections::BTreeSet::new();

    dns_set.insert("localhost".to_string());
    ip_set.insert(IpAddr::from([127, 0, 0, 1]));
    ip_set.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));

    if let Some(h) = hostname {
        let t = h.trim().to_ascii_lowercase();
        if !t.is_empty() {
            dns_set.insert(t);
        }
    }

    if !bind_ip.is_unspecified() {
        ip_set.insert(bind_ip);
    }

    // Optional extra host SAN for operator-provided hostname/IP (e.g. public domain).
    if let Some(raw) = client_host {
        let t = raw.trim().to_ascii_lowercase();
        if !t.is_empty() {
            if let Ok(ip) = t.parse::<IpAddr>() {
                ip_set.insert(ip);
            } else {
                dns_set.insert(t);
            }
        }
    }

    (dns_set.into_iter().collect(), ip_set.into_iter().collect())
}

pub(super) enum CertStatus {
    Valid { not_after: OffsetDateTime },
    /// Expired, and issued by the CA processmaster generates: safe to renew in place.
    ExpiredAutogen { not_after: OffsetDateTime },
    /// Expired, but somebody else's: we hold no key that can re-sign it.
    ExpiredForeign { not_after: OffsetDateTime },
    /// Could not be established. Never treat this as "valid" silently.
    Unknown { reason: String },
}

pub(super) async fn server_cert_status(cert_path: &str, now: OffsetDateTime) -> CertStatus {
    let bytes = match tokio::fs::read(cert_path).await {
        Ok(b) => b,
        Err(e) => return CertStatus::Unknown { reason: format!("cannot read: {e}") },
    };
    let mut reader: &[u8] = &bytes;
    let chain: Vec<CertificateDer<'static>> = match rustls_pemfile::certs(&mut reader).collect() {
        Ok(v) => v,
        Err(e) => return CertStatus::Unknown { reason: format!("cannot parse PEM: {e}") },
    };
    // The leaf comes first by rustls convention; that is the one clients validate.
    let Some(leaf) = chain.first() else {
        return CertStatus::Unknown { reason: "no certificates in file".to_string() };
    };
    let Some((not_after, issuer)) = cert_not_after_and_issuer(leaf.as_ref()) else {
        return CertStatus::Unknown { reason: "unrecognised certificate structure".to_string() };
    };
    if not_after > now {
        return CertStatus::Valid { not_after };
    }
    if issuer
        .windows(AUTOGEN_CA_COMMON_NAME.len())
        .any(|w| w == AUTOGEN_CA_COMMON_NAME.as_bytes())
    {
        CertStatus::ExpiredAutogen { not_after }
    } else {
        CertStatus::ExpiredForeign { not_after }
    }
}

/// Recovers `notAfter` and the raw issuer name from a DER certificate.
///
/// Hand-rolled because neither of our TLS crates can answer this: rustls only checks
/// validity when acting as a *client*, and rcgen only writes certificates. This walks
/// exactly as far into the structure as it must and returns `None` the moment anything
/// is unexpected -- callers must treat that as "unknown", never as "valid".
///
///   Certificate ::= SEQUENCE { tbsCertificate, ... }
///   TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
///                                 issuer, validity, ... }
///   Validity ::= SEQUENCE { notBefore Time, notAfter Time }
pub(super) fn cert_not_after_and_issuer(der: &[u8]) -> Option<(OffsetDateTime, &[u8])> {
    const SEQUENCE: u8 = 0x30;
    const CONTEXT_0: u8 = 0xa0;

    let (tag, cert_body, _) = der_take(der)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, tbs, _) = der_take(cert_body)?;
    if tag != SEQUENCE {
        return None;
    }
    // version is [0] EXPLICIT and optional (absent means v1).
    let (tag, _, after_version) = der_take(tbs)?;
    let rest = if tag == CONTEXT_0 { after_version } else { tbs };
    let (_, _, rest) = der_take(rest)?; // serialNumber
    let (_, _, rest) = der_take(rest)?; // signature AlgorithmIdentifier
    let (_, issuer, rest) = der_take(rest)?; // issuer Name
    let (tag, validity, _) = der_take(rest)?;
    if tag != SEQUENCE {
        return None;
    }
    let (_, _, after_not_before) = der_take(validity)?;
    let (tag, not_after, _) = der_take(after_not_before)?;
    Some((parse_asn1_time(tag, not_after)?, issuer))
}

/// Splits one DER TLV off the front, returning (tag, contents, remainder).
pub(super) fn der_take(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&len0, rest) = rest.split_first()?;
    let (len, rest) = if len0 < 0x80 {
        (len0 as usize, rest)
    } else {
        // Long form: the low 7 bits give the number of length bytes that follow.
        let n = (len0 & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let mut v = 0usize;
        for &b in &rest[..n] {
            v = (v << 8) | b as usize;
        }
        (v, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

pub(super) fn parse_asn1_time(tag: u8, body: &[u8]) -> Option<OffsetDateTime> {
    const UTC_TIME: u8 = 0x17;
    const GENERALIZED_TIME: u8 = 0x18;

    let s = std::str::from_utf8(body).ok()?.trim_end_matches('Z');
    // Only the UTC forms are accepted: an offset form ("...+0200") is legal ASN.1 but
    // forbidden in certificates, and guessing at one would misdate the expiry.
    let (year, rest) = match tag {
        UTC_TIME => {
            let yy: i32 = s.get(0..2)?.parse().ok()?;
            // RFC 5280: two-digit years 00..=49 are 20xx, 50..=99 are 19xx.
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, s.get(2..)?)
        }
        GENERALIZED_TIME => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    if rest.len() < 10 {
        return None;
    }
    let num = |a: usize, b: usize| -> Option<u8> { rest.get(a..b)?.parse().ok() };
    let month = time::Month::try_from(num(0, 2)?).ok()?;
    let date = time::Date::from_calendar_date(year, month, num(2, 4)?).ok()?;
    Some(
        date.with_hms(num(4, 6)?, num(6, 8)?, num(8, 10)?)
            .ok()?
            .assume_utc(),
    )
}
