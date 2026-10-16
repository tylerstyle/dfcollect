//! Modified UTF-7 mailbox names (RFC 3501 §5.1.3): `&` starts UTF-16BE in
//! base64 with `,` for `/`, `-` ends it, `&-` is a literal `&`. Commands send a
//! mailbox name back exactly as the server listed it, so only decoding is needed.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

/// Decode a mailbox name; `None` if it is not valid modified UTF-7.
pub fn decode(name: &[u8]) -> Option<String> {
    let mut out = String::new();
    let mut i = 0;
    while i < name.len() {
        let c = name[i];
        if c != b'&' {
            if !(0x20..=0x7e).contains(&c) {
                return None;
            }
            out.push(c as char);
            i += 1;
            continue;
        }
        let end = i + 1 + name[i + 1..].iter().position(|&b| b == b'-')?;
        let encoded = &name[i + 1..end];
        if encoded.is_empty() {
            out.push('&');
        } else {
            let mut bits = 0u32;
            let mut nbits = 0;
            let mut units = Vec::new();
            for &b in encoded {
                let v = B64.iter().position(|&x| x == b)? as u32;
                bits = (bits << 6) | v;
                nbits += 6;
                if nbits >= 16 {
                    nbits -= 16;
                    units.push(((bits >> nbits) & 0xffff) as u16);
                }
            }
            // Leftover bits must be zero padding
            if bits & ((1 << nbits) - 1) != 0 {
                return None;
            }
            out.push_str(&String::from_utf16(&units).ok()?);
        }
        i = end + 1;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_rfc_examples_and_umlauts() {
        assert_eq!(decode(b"INBOX").unwrap(), "INBOX");
        assert_eq!(decode(b"Entw&APw-rfe").unwrap(), "Entw\u{fc}rfe");
        assert_eq!(
            decode(b"Gel&APY-schte Elemente").unwrap(),
            "Gel\u{f6}schte Elemente"
        );
        assert_eq!(decode(b"&ZeVnLIqe-").unwrap(), "\u{65e5}\u{672c}\u{8a9e}");
        assert_eq!(decode(b"Tom &- Jerry").unwrap(), "Tom & Jerry");
        assert_eq!(
            decode(b"~peter/mail/&U,BTFw-/&ZeVnLIqe-").unwrap(),
            "~peter/mail/\u{53f0}\u{5317}/\u{65e5}\u{672c}\u{8a9e}"
        );
    }

    #[test]
    fn rejects_broken_names() {
        assert!(decode(b"&APw").is_none());
        assert!(decode(b"&A!w-").is_none());
        assert!(decode("Entw\u{fc}rfe".as_bytes()).is_none());
    }
}
