//! IMAP response syntax (RFC 3501 §9 / RFC 9051): a response is a line of
//! atoms, quoted strings, literals (`{n}` followed by n raw bytes),
//! parenthesized lists and NIL. Only what dfcollect reads is interpreted.

use anyhow::{bail, ensure, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Atom(String),
    /// Quoted string or literal: raw bytes
    Bytes(Vec<u8>),
    List(Vec<Token>),
    /// `[...]` response code or section, kept as its tokens
    Bracket(Vec<Token>),
    Nil,
}

impl Token {
    pub fn atom(&self) -> Option<&str> {
        match self {
            Token::Atom(a) => Some(a),
            _ => None,
        }
    }

    /// A string: atom, quoted or literal
    pub fn text(&self) -> Option<String> {
        match self {
            Token::Atom(a) => Some(a.clone()),
            Token::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
            _ => None,
        }
    }

    pub fn number(&self) -> Option<u64> {
        self.atom()?.parse().ok()
    }
}

/// A complete response: the raw line bytes with literals spliced in, already
/// split into tokens.
pub fn tokenize(raw: &[u8]) -> Result<Vec<Token>> {
    let mut p = Parser { b: raw, i: 0 };
    let tokens = p.sequence(None)?;
    Ok(tokens)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn sequence(&mut self, close: Option<u8>) -> Result<Vec<Token>> {
        let mut out = Vec::new();
        loop {
            while matches!(self.peek(), Some(b' ')) {
                self.i += 1;
            }
            match self.peek() {
                None | Some(b'\r') | Some(b'\n') => {
                    ensure!(close.is_none(), "unterminated list in IMAP response");
                    return Ok(out);
                }
                Some(c) if Some(c) == close => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'(') => {
                    self.i += 1;
                    out.push(Token::List(self.sequence(Some(b')'))?));
                }
                Some(b'[') => {
                    self.i += 1;
                    out.push(Token::Bracket(self.sequence(Some(b']'))?));
                }
                Some(b'"') => out.push(Token::Bytes(self.quoted()?)),
                Some(b'{') => out.push(Token::Bytes(self.literal()?)),
                Some(_) => {
                    let atom = self.atom(close);
                    if atom.eq_ignore_ascii_case("NIL") {
                        out.push(Token::Nil);
                    } else {
                        out.push(Token::Atom(atom));
                    }
                }
            }
        }
    }

    fn quoted(&mut self) -> Result<Vec<u8>> {
        self.i += 1;
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None => bail!("unterminated quoted string in IMAP response"),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    let Some(&c) = self.b.get(self.i + 1) else {
                        bail!("dangling escape in IMAP quoted string");
                    };
                    out.push(c);
                    self.i += 2;
                }
                Some(c) => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }

    /// `{n}\r\n` then n bytes (also `{n+}`, the non-synchronizing form)
    fn literal(&mut self) -> Result<Vec<u8>> {
        let start = self.i + 1;
        let end = self.b[start..]
            .iter()
            .position(|&c| c == b'}')
            .map(|p| start + p)
            .ok_or_else(|| anyhow::anyhow!("unterminated literal length"))?;
        let digits = std::str::from_utf8(&self.b[start..end])?.trim_end_matches('+');
        let n: usize = digits.parse()?;
        ensure!(
            self.b.get(end + 1..end + 3) == Some(b"\r\n"),
            "literal length not followed by CRLF"
        );
        let data_start = end + 3;
        let data = self
            .b
            .get(data_start..data_start + n)
            .ok_or_else(|| anyhow::anyhow!("literal shorter than announced"))?;
        self.i = data_start + n;
        Ok(data.to_vec())
    }

    /// Atom characters, plus `[...]` inside an atom as in `BODY[]` or
    /// `BODY[HEADER.FIELDS (DATE)]`
    fn atom(&mut self, close: Option<u8>) -> String {
        let start = self.i;
        let mut depth = 0usize;
        while let Some(c) = self.peek() {
            match c {
                b'[' => depth += 1,
                b']' if depth > 0 => depth -= 1,
                b' ' | b'(' | b'\r' | b'\n' if depth == 0 => break,
                b')' if depth == 0 => break,
                b']' if close == Some(b']') => break,
                _ => {}
            }
            self.i += 1;
        }
        String::from_utf8_lossy(&self.b[start..self.i]).into_owned()
    }
}

/// The value after `key` in a FETCH attribute list (`UID 12 FLAGS (...)`).
pub fn fetch_attr<'a>(list: &'a [Token], key: &str) -> Option<&'a Token> {
    list.chunks(2).find_map(|kv| match kv {
        [Token::Atom(k), v] if k.eq_ignore_ascii_case(key) => Some(v),
        _ => None,
    })
}

/// Month names of IMAP dates.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `INTERNALDATE` (`17-Jul-1996 02:44:25 -0700`, day may be space-padded)
/// as RFC 3339 and as ns since the Unix epoch.
pub fn internaldate(s: &str) -> Result<(String, i128)> {
    let s = s.trim();
    let bad = || anyhow::anyhow!("not an IMAP date-time: {s:?}");
    let (date, rest) = s.split_once(' ').ok_or_else(bad)?;
    let (time, zone) = rest.trim_start().split_once(' ').ok_or_else(bad)?;
    let mut d = date.split('-');
    let (day, mon, year) = (
        d.next().ok_or_else(bad)?,
        d.next().ok_or_else(bad)?,
        d.next().ok_or_else(bad)?,
    );
    let month = MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(mon))
        .ok_or_else(bad)?
        + 1;
    ensure!(
        zone.len() == 5 && (zone.starts_with('+') || zone.starts_with('-')),
        bad()
    );
    let rfc = format!(
        "{year}-{month:02}-{:02}T{time}{}:{}",
        day.trim().parse::<u32>().map_err(|_| bad())?,
        &zone[..3],
        &zone[3..]
    );
    let ns = dfcore::host::parse_rfc3339(&rfc).map_err(|_| bad())?;
    Ok((dfcore::host::rfc3339_utc_ns(ns), ns))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atom(s: &str) -> Token {
        Token::Atom(s.into())
    }

    #[test]
    fn untagged_fetch_with_literal() {
        let raw = b"* 12 FETCH (UID 4827 RFC822.SIZE 11 FLAGS (\\Seen $Junk) INTERNALDATE \"17-Jul-1996 02:44:25 -0700\" BODY[] {12}\r\nHello\r\nWorld)\r\n";
        let t = tokenize(raw).unwrap();
        assert_eq!(t[0], atom("*"));
        assert_eq!(t[1], atom("12"));
        assert_eq!(t[2], atom("FETCH"));
        let Token::List(attrs) = &t[3] else {
            panic!("{t:?}")
        };
        assert_eq!(fetch_attr(attrs, "UID").unwrap().number(), Some(4827));
        assert_eq!(
            fetch_attr(attrs, "FLAGS").unwrap(),
            &Token::List(vec![atom("\\Seen"), atom("$Junk")])
        );
        assert_eq!(
            fetch_attr(attrs, "BODY[]").unwrap(),
            &Token::Bytes(b"Hello\r\nWorld".to_vec())
        );
        assert_eq!(
            fetch_attr(attrs, "INTERNALDATE").unwrap().text().unwrap(),
            "17-Jul-1996 02:44:25 -0700"
        );
    }

    #[test]
    fn list_and_response_codes() {
        let t = tokenize(b"* LIST (\\HasNoChildren \\Noselect) \"/\" \"Sent Items\"\r\n").unwrap();
        assert_eq!(t[3], Token::Bytes(b"/".to_vec()));
        assert_eq!(t[4].text().unwrap(), "Sent Items");
        let t = tokenize(b"* LIST () NIL INBOX\r\n").unwrap();
        assert_eq!(t[3], Token::Nil);
        let t = tokenize(b"* OK [UIDVALIDITY 3857529045] UIDs valid\r\n").unwrap();
        assert_eq!(
            t[2],
            Token::Bracket(vec![atom("UIDVALIDITY"), atom("3857529045")])
        );
        let t = tokenize(b"* LIST () \"/\" {9}\r\nA \"B\" (C)\r\n").unwrap();
        assert_eq!(t[4].text().unwrap(), "A \"B\" (C)");
        let t = tokenize(b"* LIST () \"/\" \"quote\\\"d\\\\\"\r\n").unwrap();
        assert_eq!(t[4].text().unwrap(), "quote\"d\\");
    }

    #[test]
    fn broken_responses_are_errors() {
        assert!(tokenize(b"* 1 FETCH (UID 1\r\n").is_err());
        assert!(tokenize(b"* 1 FETCH (BODY[] {10}\r\nshort)\r\n").is_err());
        assert!(tokenize(b"* OK \"unterminated\r\n").is_err());
    }

    #[test]
    fn internal_dates() {
        let (rfc, ns) = internaldate("17-Jul-1996 02:44:25 -0700").unwrap();
        assert_eq!(rfc, "1996-07-17T09:44:25.000000000Z");
        assert_eq!(
            ns,
            dfcore::host::parse_rfc3339("1996-07-17T09:44:25Z").unwrap()
        );
        let (rfc, _) = internaldate(" 1-Feb-2026 23:00:00 +0100").unwrap();
        assert_eq!(rfc, "2026-02-01T22:00:00.000000000Z");
        assert!(internaldate("31-Feb-2026 00:00:00 +0000").is_err());
        assert!(internaldate("1-Foo-2026 00:00:00 +0000").is_err());
        assert!(internaldate("1-Feb-2026 00:00:00 CET").is_err());
    }
}
