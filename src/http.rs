//! A small HTTPS client for the REST APIs dfcollect reads (Microsoft Graph,
//! the Microsoft identity platform). HTTP/1.1 over the IMAP client's rustls
//! setup (system CAs and host name), keep-alive, `Content-Length` and chunked
//! bodies, no compression. 429 and 503 are waited out as `Retry-After` says.
//! Redirects are never followed, and request headers (bearer tokens) never
//! appear in errors.

use crate::mail::client::{connect_tcp, upgrade, TlsInfo};
use anyhow::{bail, ensure, Context, Result};
use rustls::{ClientConnection, StreamOwned};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    time::Duration,
};

/// Largest response body (one message)
const MAX_BODY: usize = 1 << 30;
const MAX_HEAD: usize = 64 << 10;
/// Waits for 429/503 before giving up, and the longest single wait
const MAX_RETRIES: u32 = 8;
const MAX_WAIT: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    /// Path and query
    pub target: String,
}

/// `https://host[:port]/path?query`; nothing else is accepted.
pub fn parse_url(url: &str) -> Result<Url> {
    let rest = url
        .strip_prefix("https://")
        .with_context(|| format!("{url}: only https:// URLs are used"))?;
    let (authority, target) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    ensure!(
        !authority.is_empty() && !authority.contains('@'),
        "{url}: no host"
    );
    let port = |p: &str| p.parse::<u16>().with_context(|| format!("{url}: bad port"));
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (h, after) = rest
            .split_once(']')
            .with_context(|| format!("{url}: bad IPv6 address"))?;
        match after {
            "" => (h, 443),
            _ => (
                h,
                port(
                    after
                        .strip_prefix(':')
                        .with_context(|| format!("{url}: bad port"))?,
                )?,
            ),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, port(p)?),
            None => (authority, 443),
        }
    };
    Ok(Url {
        host: host.to_ascii_lowercase(),
        port,
        target: target.to_string(),
    })
}

/// Percent-encoding for a path segment or a query value (RFC 3986 unreserved
/// characters stay)
pub fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `application/x-www-form-urlencoded`
pub fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> Result<Value> {
        serde_json::from_slice(&self.body).with_context(|| {
            format!(
                "HTTP {}: the body is not JSON: {}",
                self.status,
                String::from_utf8_lossy(&self.body[..self.body.len().min(200)])
            )
        })
    }

    /// The API's own error text, for messages (Graph and the identity
    /// platform both answer `{"error": ...}`)
    pub fn error_text(&self) -> String {
        match serde_json::from_slice::<Value>(&self.body) {
            Ok(v) => match &v["error"] {
                Value::String(code) => format!(
                    "{code}: {}",
                    v["error_description"].as_str().unwrap_or_default()
                ),
                Value::Object(e) => format!(
                    "{}: {}",
                    e.get("code").and_then(Value::as_str).unwrap_or("?"),
                    e.get("message").and_then(Value::as_str).unwrap_or_default()
                ),
                _ => String::from_utf8_lossy(&self.body[..self.body.len().min(200)]).into_owned(),
            },
            Err(_) => String::from_utf8_lossy(&self.body[..self.body.len().min(200)]).into_owned(),
        }
    }
}

fn read_line<R: BufRead>(r: &mut R, limit: usize) -> Result<String> {
    let mut line = Vec::new();
    r.by_ref().take(limit as u64).read_until(b'\n', &mut line)?;
    ensure!(
        line.ends_with(b"\n"),
        "HTTP: line too long or connection closed"
    );
    while line.last().is_some_and(|c| *c == b'\n' || *c == b'\r') {
        line.pop();
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Read one response. Returns it and whether the connection may be reused.
pub fn read_response<R: BufRead>(r: &mut R, head: bool) -> Result<(Response, bool)> {
    let status_line = read_line(r, MAX_HEAD)?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    ensure!(
        version.starts_with("HTTP/1."),
        "HTTP: unexpected status line {status_line:?}"
    );
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .with_context(|| format!("HTTP: unexpected status line {status_line:?}"))?;
    let mut headers = Vec::new();
    let mut total = status_line.len();
    loop {
        let line = read_line(r, MAX_HEAD)?;
        total += line.len();
        ensure!(total <= MAX_HEAD, "HTTP: response head too large");
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _): &&(String, String)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let mut keep_alive = version == "HTTP/1.1"
        && !get("Connection").is_some_and(|c| c.eq_ignore_ascii_case("close"));
    let mut body = Vec::new();
    if head || status == 204 || status == 304 || (100..200).contains(&status) {
        // no body
    } else if get("Transfer-Encoding").is_some_and(|t| t.to_ascii_lowercase().contains("chunked")) {
        loop {
            let line = read_line(r, 1024)?;
            let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                .with_context(|| format!("HTTP: bad chunk size {line:?}"))?;
            if size == 0 {
                // trailers
                while !read_line(r, MAX_HEAD)?.is_empty() {}
                break;
            }
            ensure!(
                body.len() + size <= MAX_BODY,
                "HTTP: body larger than {MAX_BODY} bytes"
            );
            let start = body.len();
            body.resize(start + size, 0);
            r.read_exact(&mut body[start..])
                .context("HTTP: connection closed inside a chunk")?;
            ensure!(read_line(r, 2)?.is_empty(), "HTTP: chunk without CRLF");
        }
    } else if let Some(len) = get("Content-Length") {
        let len: usize = len.parse().context("HTTP: bad Content-Length")?;
        ensure!(len <= MAX_BODY, "HTTP: body larger than {MAX_BODY} bytes");
        body.resize(len, 0);
        r.read_exact(&mut body)
            .context("HTTP: connection closed before the whole body")?;
    } else {
        // Until the server closes
        keep_alive = false;
        match r.take(MAX_BODY as u64 + 1).read_to_end(&mut body) {
            Ok(_) => {}
            // Servers that close without TLS close_notify
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            Err(e) => return Err(e.into()),
        }
        ensure!(
            body.len() <= MAX_BODY,
            "HTTP: body larger than {MAX_BODY} bytes"
        );
    }
    Ok((
        Response {
            status,
            headers,
            body,
        },
        keep_alive,
    ))
}

/// Seconds to wait from `Retry-After` (seconds; an HTTP date counts as 30)
pub fn retry_after(value: Option<&str>) -> u64 {
    match value {
        Some(v) => v.trim().parse::<u64>().unwrap_or(30).clamp(1, MAX_WAIT),
        None => 10,
    }
}

type Tls = StreamOwned<ClientConnection, TcpStream>;

pub struct Client {
    conn: Option<(String, BufReader<Tls>)>,
    timeout: Duration,
    /// The TLS session of the first connection to each host
    pub tls: BTreeMap<String, TlsInfo>,
    pub requests: u64,
    pub waits: u64,
    pub sent: u64,
    pub received: u64,
    /// The run's console and stop: server-requested waits are reported there
    /// and end early on a stop. None: the terminal, uninterrupted
    run: Option<(
        std::sync::Arc<dyn crate::console::Console>,
        &'static crate::common::Stop,
    )>,
}

impl Client {
    pub fn new(timeout: Duration) -> Self {
        Self {
            conn: None,
            timeout,
            tls: BTreeMap::new(),
            requests: 0,
            waits: 0,
            sent: 0,
            received: 0,
            run: None,
        }
    }

    /// Report waits to the run's console and end them on a stop
    pub fn for_run(mut self, ctx: &crate::common::RunCtx) -> Self {
        self.run = Some((ctx.console.clone(), ctx.stop));
        self
    }

    fn connect(&mut self, url: &Url) -> Result<BufReader<Tls>> {
        let tcp = connect_tcp(&url.host, url.port, self.timeout)?;
        let (tls, info) = upgrade(tcp, &url.host, None)?;
        self.tls
            .entry(format!("{}:{}", url.host, url.port))
            .or_insert(info);
        Ok(BufReader::new(tls))
    }

    fn once(
        &mut self,
        method: &str,
        url: &Url,
        headers: &[(&str, &str)],
        body: Option<(&str, &[u8])>,
    ) -> Result<Response> {
        let key = format!("{}:{}", url.host, url.port);
        let reused = matches!(&self.conn, Some((k, _)) if *k == key);
        let mut stream = match self.conn.take() {
            Some((k, s)) if k == key => s,
            _ => self.connect(url)?,
        };
        let mut req = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: dfcollect/{}\r\nAccept-Encoding: identity\r\n",
            url.target,
            if url.port == 443 { url.host.clone() } else { key.clone() },
            crate::VERSION
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some((ctype, data)) = body {
            req.push_str(&format!(
                "Content-Type: {ctype}\r\nContent-Length: {}\r\n",
                data.len()
            ));
        }
        req.push_str("\r\n");
        let result = (|| -> Result<(Response, bool)> {
            let w = stream.get_mut();
            w.write_all(req.as_bytes())?;
            if let Some((_, data)) = body {
                w.write_all(data)?;
            }
            w.flush()?;
            read_response(&mut stream, method == "HEAD")
        })();
        match result {
            Ok((resp, keep)) => {
                self.requests += 1;
                self.sent += (req.len() + body.map_or(0, |(_, d)| d.len())) as u64;
                self.received += resp.body.len() as u64;
                if keep {
                    self.conn = Some((key, stream));
                }
                Ok(resp)
            }
            // A kept connection the server closed meanwhile: once more, fresh
            Err(_) if reused => self.once(method, url, headers, body),
            Err(e) => Err(e.context(format!(
                "{method} https://{key}{}",
                strip_query(&url.target)
            ))),
        }
    }

    /// One request; 429 and 503 are retried after `Retry-After`.
    pub fn request(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<(&str, &[u8])>,
    ) -> Result<Response> {
        let parsed = parse_url(url)?;
        let mut tries = 0;
        loop {
            let resp = self.once(method, &parsed, headers, body)?;
            if (resp.status == 429 || resp.status == 503) && tries < MAX_RETRIES {
                tries += 1;
                self.waits += 1;
                let secs = retry_after(resp.header("Retry-After"));
                let text = format!(
                    "{} {}: HTTP {}, waiting {secs} s as the server asks",
                    method,
                    strip_query(&parsed.target),
                    resp.status
                );
                match &self.run {
                    Some((console, stop)) => {
                        console.notice(crate::console::Level::Info, &text);
                        crate::common::sleep_unless_stopped(stop, Duration::from_secs(secs))?;
                    }
                    None => {
                        eprintln!("[*] {text}");
                        std::thread::sleep(Duration::from_secs(secs));
                    }
                }
                continue;
            }
            if (300..400).contains(&resp.status) {
                bail!(
                    "{method} {}: HTTP {} redirect to {:?} not followed",
                    strip_query(&parsed.target),
                    resp.status,
                    resp.header("Location")
                );
            }
            return Ok(resp);
        }
    }
}

/// A request target without its query, for messages
pub fn strip_query(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> (Response, bool) {
        read_response(&mut std::io::Cursor::new(raw.as_bytes().to_vec()), false).unwrap()
    }

    #[test]
    fn urls() {
        assert_eq!(
            parse_url("https://graph.microsoft.com/v1.0/me?x=1").unwrap(),
            Url {
                host: "graph.microsoft.com".into(),
                port: 443,
                target: "/v1.0/me?x=1".into()
            }
        );
        assert_eq!(parse_url("https://Server:8443").unwrap().port, 8443);
        assert_eq!(parse_url("https://[::1]:8443/a").unwrap().host, "::1");
        assert_eq!(parse_url("https://[::1]/a").unwrap().port, 443);
        assert!(parse_url("https://[::1]x/a").is_err());
        assert!(parse_url("http://graph.microsoft.com/").is_err());
        assert!(parse_url("https://user@host/").is_err());
        assert_eq!(encode("a b/c'=é"), "a%20b%2Fc%27%3D%C3%A9");
        assert_eq!(form(&[("scope", "a b"), ("x", "1")]), "scope=a%20b&x=1");
    }

    #[test]
    fn content_length_and_chunked_bodies() {
        let (r, keep) = parse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: b\r\n\r\nhello");
        assert_eq!(
            (r.status, r.body.as_slice(), keep),
            (200, &b"hello"[..], true)
        );
        assert_eq!(r.header("x-a"), Some("b"));
        let (r, keep) = parse(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nTrailer: x\r\n\r\n",
        );
        assert_eq!((r.body.as_slice(), keep), (&b"Wikipedia"[..], false));
        let (r, keep) = parse("HTTP/1.0 200 OK\r\n\r\nuntil close");
        assert_eq!((r.body.as_slice(), keep), (&b"until close"[..], false));
        let (r, _) = parse("HTTP/1.1 204 No Content\r\n\r\n");
        assert!(r.body.is_empty());
        assert!(read_response(
            &mut std::io::Cursor::new(
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort".to_vec()
            ),
            false
        )
        .is_err());
        assert!(read_response(
            &mut std::io::Cursor::new(b"SSH-2.0\r\n\r\n".to_vec()),
            false
        )
        .is_err());
    }

    #[test]
    fn errors_and_waits() {
        let body = r#"{"error":"authorization_pending","error_description":"wait"}"#;
        let (r, _) = parse(&format!(
            "HTTP/1.1 400 Bad\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ));
        assert_eq!(r.error_text(), "authorization_pending: wait");
        let body = r#"{"error":{"code":"ErrorItemNotFound","message":"gone"}}"#;
        let (r, _) = parse(&format!(
            "HTTP/1.1 404 NF\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ));
        assert_eq!(r.error_text(), "ErrorItemNotFound: gone");
        assert_eq!(retry_after(Some("7")), 7);
        assert_eq!(retry_after(Some("Wed, 21 Oct 2015 07:28:00 GMT")), 30);
        assert_eq!(retry_after(Some("100000")), MAX_WAIT);
        assert_eq!(retry_after(None), 10);
    }
}
