/// Constant-time string comparison, so a secret cannot be recovered byte-by-byte via
/// timing. Length is not treated as secret: a mismatch fails fast.
pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_matches_ordinary_equality() {
        assert!(ct_eq("", ""));
        assert!(ct_eq("admin", "admin"));
        assert!(ct_eq(&"x".repeat(64), &"x".repeat(64)));
        assert!(!ct_eq("admin", "admln"));
        assert!(!ct_eq("admin", "admi"));
        assert!(!ct_eq("", "a"));
        // A difference in the last byte must be caught as reliably as the first.
        assert!(!ct_eq("aaaaaaaaZ", "aaaaaaaaY"));
        assert!(!ct_eq("Zaaaaaaaa", "Yaaaaaaaa"));
    }
}
