//! Pathname checks applied before authorization or credential injection.
//!
//! Two levels exist. [`is_clean_pathname`] is cheap hygiene enforced on every
//! request. [`is_unambiguous_pathname`] additionally refuses paths that an
//! upstream could decode into a different route; it only matters when the
//! authorizing rule constrains pathnames, because such a rule matched the
//! literal path rather than the route the upstream eventually serves.

/// The maximum number of percent-decoding rounds checked before a path is ambiguous.
const MAX_DECODING_ROUNDS: usize = 8;

/// Reject literal backslashes and control characters at every percent-decoding level.
///
/// This applies to every request, whatever rule matches. No legitimate HTTP
/// path carries control characters, and decoded NUL, CR, or LF bytes can
/// truncate or split requests in upstream parsers. A literal backslash is
/// invalid URI syntax that some servers treat as a separator. Encoding that
/// does not settle within the decoding budget is refused too, since it could
/// hide a control character deeper than this check looks. Encoded separators
/// and dot segments are left to [`is_unambiguous_pathname`].
pub fn is_clean_pathname(path: &str) -> bool {
    if path.contains('\\') {
        return false;
    }
    let mut decoded = path.as_bytes().to_vec();
    for _ in 0..MAX_DECODING_ROUNDS {
        if decoded.iter().any(u8::is_ascii_control) {
            return false;
        }
        let next = decode_once(&decoded);
        if next == decoded {
            return true;
        }
        decoded = next;
    }
    false
}

/// Reject traversal and ambiguous separators at every percent-decoding level.
///
/// Repeated encoding is checked as well as the literal request. Excessive
/// encoding is ambiguous, so it is rejected instead of guessing how many times
/// an upstream decodes. Every unambiguous pathname is also clean.
pub fn is_unambiguous_pathname(path: &str) -> bool {
    let mut decoded = path.as_bytes().to_vec();
    for _ in 0..MAX_DECODING_ROUNDS {
        if has_unsafe_bytes(&decoded)
            || has_dot_segment(&decoded)
            || has_encoded_separator(&decoded)
        {
            return false;
        }
        let next = decode_once(&decoded);
        if next == decoded {
            return true;
        }
        decoded = next;
    }
    false
}

/// Detect control characters and backslashes, which some servers treat as separators.
fn has_unsafe_bytes(path: &[u8]) -> bool {
    path.iter().any(|byte| byte.is_ascii_control() || *byte == b'\\')
}

/// Detect `.` and `..` segments, including those followed by `;` parameters.
fn has_dot_segment(path: &[u8]) -> bool {
    path.split(|byte| *byte == b'/').any(|segment| {
        let name = segment.split(|byte| *byte == b';').next().unwrap_or_default();
        name == b"." || name == b".."
    })
}

/// Detect an encoded separator, which can change which route a path rule authorizes.
fn has_encoded_separator(path: &[u8]) -> bool {
    (0..path.len())
        .any(|index| matches!(encoded_byte(path, index), Some(b'/' | b'\\' | b'?' | b'#')))
}

/// Percent-decode every valid `%XX` escape once, keeping other bytes as they are.
fn decode_once(path: &[u8]) -> Vec<u8> {
    let mut next = Vec::with_capacity(path.len());
    let mut index = 0;
    while index < path.len() {
        if let Some(byte) = encoded_byte(path, index) {
            next.push(byte);
            index += 3;
        } else {
            next.push(path[index]);
            index += 1;
        }
    }
    next
}

/// Decode a `%XX` escape starting at `index`, if one is present.
fn encoded_byte(path: &[u8], index: usize) -> Option<u8> {
    if path[index] != b'%' {
        return None;
    }
    let hex = path.get(index + 1..index + 3)?;
    let high = char::from(hex[0]).to_digit(16)?;
    let low = char::from(hex[1]).to_digit(16)?;
    Some((high * 16 + low) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deny traversal at each decoding level while preserving ordinary encoded filenames.
    #[test]
    fn checks_path_segments_before_forwarding() {
        for path in [
            "/allowed/../private",
            "/allowed/./private",
            "/allowed/%2e%2E/private",
            "/allowed/.%2e/private",
            "/allowed/%252e%252e/private",
            "/allowed/..;ignored/private",
            "/allowed/%2f../private",
            "/allowed/%5c../private",
            "/allowed\\..\\private",
            "/allowed/%00/private",
            "/allowed/%253fprivate",
            "/allowed/%2523private",
            "/@scope%2Fname",
        ] {
            assert!(!is_unambiguous_pathname(path), "must reject {path}");
        }
        for path in [
            "/",
            "/allowed/file.txt",
            "/allowed/a%20b",
            "/allowed/%E2%82%AC",
            "/allowed/.config",
            "/allowed/a..b",
            "/allowed/100%25",
        ] {
            assert!(is_unambiguous_pathname(path), "must preserve {path}");
            assert!(is_clean_pathname(path), "must preserve {path}");
        }
    }

    /// Hygiene refuses control characters and literal backslashes but keeps
    /// encoded separators and dot segments for rules without path constraints.
    #[test]
    fn clean_pathnames_allow_encoded_separators_and_dot_segments() {
        for path in [
            "/allowed\\..\\private",
            "/allowed/%00/private",
            "/allowed/%0d%0aHost:%20evil",
            "/allowed/%2500/private",
            "/allowed/%7F",
        ] {
            assert!(!is_clean_pathname(path), "must reject {path}");
        }
        for path in [
            "/@scope%2Fname",
            "/api/v4/projects/group%2frepo",
            "/a/%2e%2e/b",
            "/a/../b",
            "/bucket/key%5Cwith%5Cbackslashes",
            "/search%3Fq%23x",
            "/allowed/%252e%252e/private",
        ] {
            assert!(is_clean_pathname(path), "must preserve {path}");
        }
    }

    /// Paths that never stabilize within the decoding budget are ambiguous and unclean.
    #[test]
    fn rejects_excessive_encoding() {
        let mut path = "/a%41".to_owned();
        for _ in 0..MAX_DECODING_ROUNDS {
            path = path.replace('%', "%25");
        }
        assert!(!is_unambiguous_pathname(&path));
        assert!(!is_clean_pathname(&path));
        assert!(is_unambiguous_pathname("/a%2541"));
        assert!(is_clean_pathname("/a%2541"));
    }
}
