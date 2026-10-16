//! A small IMAP client: TLS (implicit or STARTTLS) with rustls, responses
//! with literals, tagged commands, SASL. It sends only what the caller asks
//! for; secrets never appear in errors.

use super::parse::{tokenize, Token};
use anyhow::{bail, ensure, Context, Result};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned,
};
use sha2::Digest;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

/// Largest literal accepted (one message body)
const MAX_LITERAL: usize = 4 << 30;
/// Longest response line without literals
const MAX_LINE: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Security {
    /// TLS from the first byte (port 993)
    Tls,
    /// Plain connection upgraded with STARTTLS (port 143)
    StartTls,
    /// No encryption: test setups only
    Plaintext,
}

/// What the TLS session was, for the record.
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub version: String,
    pub cipher: String,
    /// DER of the certificates the server sent, leaf first
    pub chain: Vec<Vec<u8>>,
    pub verified_by: String,
}

pub fn sha256_hex(data: &[u8]) -> String {
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (k, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if k <= chunk.len() {
                out.push(T[((n >> shift) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Accepts exactly one leaf certificate, named by its SHA-256, whatever its
/// issuer and names: for servers with an internal CA, after the examiner
/// compared the fingerprint on a trusted channel. Handshake signatures are
/// still checked.
#[derive(Debug)]
struct PinnedLeaf {
    sha256: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedLeaf {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let got = sha256_hex(end_entity.as_ref());
        if got == self.sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "server certificate SHA-256 {got} is not the pinned {}",
                self.sha256
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_config(pin: Option<&str>) -> Result<(ClientConfig, String)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("TLS configuration")?;
    if let Some(pin) = pin {
        let config = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedLeaf {
                sha256: pin.to_ascii_lowercase(),
                provider,
            }))
            .with_no_client_auth();
        return Ok((config, format!("pinned leaf certificate SHA-256 {pin}")));
    }
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    ensure!(
        !roots.is_empty(),
        "no trusted CA certificates found on this system; pin the server certificate with --tls-sha256"
    );
    Ok((
        builder.with_root_certificates(roots).with_no_client_auth(),
        "system CA certificates and host name".into(),
    ))
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

pub struct Connection {
    stream: Box<dyn Stream>,
    rbuf: Vec<u8>,
    tag: u32,
    pub peer: SocketAddr,
    pub sent: u64,
    pub received: u64,
}

fn upgrade(
    tcp: TcpStream,
    host: &str,
    pin: Option<&str>,
) -> Result<(StreamOwned<ClientConnection, TcpStream>, TlsInfo)> {
    let (config, verified_by) = tls_config(pin)?;
    let name = ServerName::try_from(host.to_string()).context("server name for TLS")?;
    let conn = ClientConnection::new(Arc::new(config), name).context("TLS session")?;
    let mut tls = StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .with_context(|| format!("TLS handshake with {host}"))?;
    }
    let info = TlsInfo {
        version: format!("{:?}", tls.conn.protocol_version().context("TLS version")?),
        cipher: format!(
            "{:?}",
            tls.conn
                .negotiated_cipher_suite()
                .context("TLS cipher suite")?
                .suite()
        ),
        chain: tls
            .conn
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .map(|c| c.as_ref().to_vec())
            .collect(),
        verified_by,
    };
    Ok((tls, info))
}

/// A line ending in `{n}\r\n` or `{n+}\r\n` announces a literal of n bytes.
fn literal_len(line: &[u8]) -> Option<usize> {
    let body = line.strip_suffix(b"}\r\n")?;
    let open = body.iter().rposition(|&c| c == b'{')?;
    let digits = std::str::from_utf8(&body[open + 1..]).ok()?;
    digits.trim_end_matches('+').parse().ok()
}

/// A quoted IMAP string; `None` for text that needs a literal.
pub fn quote(s: &str) -> Option<String> {
    if s.bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == 0 || b >= 0x80)
    {
        return None;
    }
    Some(format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

impl Connection {
    /// Connect with implicit TLS or in plaintext and read the greeting. For
    /// STARTTLS see [`connect_starttls`].
    pub fn connect(
        host: &str,
        port: u16,
        tls: bool,
        pin: Option<&str>,
        timeout: Duration,
    ) -> Result<(Self, Option<TlsInfo>, Vec<Token>)> {
        let tcp = connect_tcp(host, port, timeout)?;
        let peer = tcp.peer_addr()?;
        let (stream, info): (Box<dyn Stream>, Option<TlsInfo>) = if tls {
            let (tls, info) = upgrade(tcp, host, pin)?;
            (Box::new(tls), Some(info))
        } else {
            (Box::new(tcp), None)
        };
        let mut conn = Connection {
            stream,
            rbuf: Vec::new(),
            tag: 1,
            peer,
            sent: 0,
            received: 0,
        };
        let greeting = conn.greeting()?;
        Ok((conn, info, greeting))
    }

    fn greeting(&mut self) -> Result<Vec<Token>> {
        let greeting = tokenize(&self.read_response()?)?;
        match greeting.get(1).and_then(Token::atom) {
            Some(s) if s.eq_ignore_ascii_case("OK") || s.eq_ignore_ascii_case("PREAUTH") => {
                Ok(greeting)
            }
            _ => bail!("the server's greeting refuses the connection: {greeting:?}"),
        }
    }

    fn read_more(&mut self) -> Result<()> {
        let mut buf = [0u8; 64 * 1024];
        let n = loop {
            match self.stream.read(&mut buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("reading from the IMAP server"),
            }
        };
        ensure!(n > 0, "the IMAP server closed the connection");
        self.received += n as u64;
        self.rbuf.extend_from_slice(&buf[..n]);
        Ok(())
    }

    fn read_line(&mut self) -> Result<Vec<u8>> {
        let mut searched = 0;
        loop {
            if let Some(p) = self.rbuf[searched..].windows(2).position(|w| w == b"\r\n") {
                let end = searched + p + 2;
                return Ok(self.rbuf.drain(..end).collect());
            }
            searched = self.rbuf.len().saturating_sub(1);
            ensure!(self.rbuf.len() <= MAX_LINE, "IMAP response line too long");
            self.read_more()?;
        }
    }

    /// One complete response, literals included.
    pub fn read_response(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let line = self.read_line()?;
            out.extend_from_slice(&line);
            let Some(n) = literal_len(&line) else {
                return Ok(out);
            };
            ensure!(n <= MAX_LITERAL, "IMAP literal of {n} bytes is too large");
            while self.rbuf.len() < n {
                self.read_more()?;
            }
            out.extend(self.rbuf.drain(..n));
        }
    }

    fn send(&mut self, line: &[u8]) -> Result<()> {
        self.stream
            .write_all(line)
            .context("writing to the IMAP server")?;
        self.stream.flush()?;
        self.sent += line.len() as u64;
        Ok(())
    }

    fn next_tag(&mut self) -> String {
        let tag = format!("D{:05}", self.tag);
        self.tag += 1;
        tag
    }

    fn finish_tagged(tag: &str, display: &str, tokens: Vec<Token>) -> Result<Vec<Token>> {
        let status = tokens.get(1).and_then(Token::atom).unwrap_or_default();
        if status.eq_ignore_ascii_case("OK") {
            return Ok(tokens);
        }
        let text: Vec<String> = tokens[2..].iter().filter_map(Token::text).collect();
        bail!(
            "{display}: server answered {status} {} ({tag})",
            text.join(" ")
        )
    }

    /// Send `command` and pass every untagged response to `untagged` (tokens
    /// and raw bytes). `display` stands for the command in errors.
    pub fn command(
        &mut self,
        command: &str,
        display: &str,
        mut untagged: impl FnMut(Vec<Token>, &[u8]) -> Result<()>,
    ) -> Result<Vec<Token>> {
        let tag = self.next_tag();
        self.send(format!("{tag} {command}\r\n").as_bytes())?;
        loop {
            let raw = self.read_response()?;
            let tokens =
                tokenize(&raw).with_context(|| format!("{display}: unreadable response"))?;
            match tokens.first().and_then(Token::atom) {
                Some(t) if t == tag => return Self::finish_tagged(&tag, display, tokens),
                Some("*") => untagged(tokens, &raw)?,
                Some("+") => bail!("{display}: unexpected continuation request"),
                _ => bail!(
                    "{display}: unexpected response {:?}",
                    String::from_utf8_lossy(&raw)
                ),
            }
        }
    }

    /// SASL `AUTHENTICATE` with one initial response; secrets go only to the
    /// socket.
    pub fn authenticate(&mut self, mechanism: &str, response: &[u8]) -> Result<Vec<Token>> {
        let tag = self.next_tag();
        let display = format!("AUTHENTICATE {mechanism}");
        self.send(format!("{tag} AUTHENTICATE {mechanism}\r\n").as_bytes())?;
        let mut answered = false;
        loop {
            let raw = self.read_response()?;
            let tokens =
                tokenize(&raw).with_context(|| format!("{display}: unreadable response"))?;
            match tokens.first().and_then(Token::atom) {
                Some(t) if t == tag => return Self::finish_tagged(&tag, &display, tokens),
                Some("+") if !answered => {
                    answered = true;
                    let mut line = base64(response).into_bytes();
                    line.extend_from_slice(b"\r\n");
                    self.send(&line)?;
                }
                // A second challenge carries an error (XOAUTH2); an empty
                // answer makes the server finish with NO
                Some("+") => self.send(b"\r\n")?,
                Some("*") => {}
                _ => bail!("{display}: unexpected response"),
            }
        }
    }

    /// `LOGIN` with quoted strings; the password is never shown.
    pub fn login(&mut self, user: &str, password: &str) -> Result<Vec<Token>> {
        let (Some(u), Some(p)) = (quote(user), quote(password)) else {
            bail!("LOGIN cannot carry this user name or password; use --auth plain");
        };
        self.command(
            &format!("LOGIN {u} {p}"),
            &format!("LOGIN {u} <password>"),
            |_, _| Ok(()),
        )
    }
}

fn connect_tcp(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("Cannot resolve {host}"))?
        .collect();
    let mut last = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(tcp) => {
                tcp.set_read_timeout(Some(timeout))?;
                tcp.set_write_timeout(Some(timeout))?;
                return Ok(tcp);
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("no address")))
    .with_context(|| format!("Cannot connect to {host}:{port}"))
}

/// Connect for STARTTLS: plain greeting, `STARTTLS`, then TLS on the same
/// socket.
pub fn connect_starttls(
    host: &str,
    port: u16,
    pin: Option<&str>,
    timeout: Duration,
) -> Result<(Connection, TlsInfo, Vec<Token>)> {
    let tcp = connect_tcp(host, port, timeout)?;
    let peer = tcp.peer_addr()?;
    let mut plain = Connection {
        stream: Box::new(tcp.try_clone()?),
        rbuf: Vec::new(),
        tag: 1,
        peer,
        sent: 0,
        received: 0,
    };
    let greeting = plain.greeting()?;
    plain.command("STARTTLS", "STARTTLS", |_, _| Ok(()))?;
    ensure!(
        plain.rbuf.is_empty(),
        "the server sent data after STARTTLS before the TLS handshake"
    );
    let (sent, received, tag) = (plain.sent, plain.received, plain.tag);
    drop(plain);
    let (tls, info) = upgrade(tcp, host, pin)?;
    Ok((
        Connection {
            stream: Box::new(tls),
            rbuf: Vec::new(),
            tag,
            peer,
            sent,
            received,
        },
        info,
        greeting,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), want);
        }
        assert_eq!(base64(b"\0anna\0secret"), "AGFubmEAc2VjcmV0");
    }

    #[test]
    fn literal_lengths_and_quoting() {
        assert_eq!(literal_len(b"* 1 FETCH (BODY[] {42}\r\n"), Some(42));
        assert_eq!(literal_len(b"* LIST () \"/\" {7+}\r\n"), Some(7));
        assert_eq!(literal_len(b"* OK done\r\n"), None);
        assert_eq!(quote("an\"na").unwrap(), "\"an\\\"na\"");
        assert!(quote("p\u{e4}ss").is_none());
        assert!(quote("a\r\nb").is_none());
    }
}
