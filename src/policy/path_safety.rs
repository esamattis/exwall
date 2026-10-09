//! Rejection of ambiguous request pathnames before authorization or credential injection.

/// The maximum number of percent-decoding rounds checked before a path is ambiguous.
const MAX_DECODING_ROUNDS: usize = 8;

/// Reject traversal and ambiguous separators at every percent-decoding level.
///
/// Repeated encoding is checked as well as the literal request. Excessive
/// encoding is ambiguous, so it is rejected instead of guessing how many times
/// an upstream decodes.
pub fn is_safe_pathname(path: &str) -> bool {
    let mut decoded = path.as_bytes().to_vec();
    for _ in 0..MAX_DECODING_ROUNDS {
        if has_unsafe_bytes(&decoded) || has_dot_segment(&decoded) {
            return false;
        }
        let Some(next) = decode_once(&decoded) else {
            return false;
        };
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

/// Percent-decode once, returning `None` when an encoded separator would change routing.
fn decode_once(path: &[u8]) -> Option<Vec<u8>> {
    let mut next = Vec::with_capacity(path.len());
    let mut index = 0;
    while index < path.len() {
        if let Some(byte) = encoded_byte(path, index) {
            // An encoded separator can change which route a path rule authorizes.
            if matches!(byte, b'/' | b'\\' | b'?' | b'#') {
                return None;
            }
            next.push(byte);
            index += 3;
        } else {
            next.push(path[index]);
            index += 1;
        }
    }
    Some(next)
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
        ] {
            assert!(!is_safe_pathname(path), "must reject {path}");
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
            assert!(is_safe_pathname(path), "must preserve {path}");
        }
    }

    /// Paths that never stabilize within the decoding budget are ambiguous.
    #[test]
    fn rejects_excessive_encoding() {
        let mut path = "/a%41".to_owned();
        for _ in 0..MAX_DECODING_ROUNDS {
            path = path.replace('%', "%25");
        }
        assert!(!is_safe_pathname(&path));
        assert!(is_safe_pathname("/a%2541"));
    }
}
