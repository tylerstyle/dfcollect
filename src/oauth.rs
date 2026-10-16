//! Sign-in to Microsoft Graph (Microsoft identity platform) and Gmail (Google
//! OAuth 2.0):
//! - Microsoft Graph:
//!   - device code (delegated): scopes `Mail.Read` and `offline_access`;
//!   - client credentials (application permission `Mail.Read`);
//! - Google Gmail (`https://www.googleapis.com/auth/gmail.readonly`):
//!   - service account with domain-wide delegation (RS256 JWT assertion);
//!   - installed desktop app (authorization code with PKCE S256 via loopback
//!     listener or redirect URL pasted on stdin, renewed with refresh token);
//! - an access token from a file, obtained some other way (not renewed).
//!
//! Tokens and secrets stay in memory. The record holds the method, client,
//! tenant/subject, granted scopes and the claims in the token that name the
//! account and the app (read, not verified: the API verifies them).

use crate::http::{form, Client};
use anyhow::{bail, ensure, Context, Result};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{RsaKeyPair, RSA_PKCS1_SHA256},
};
use serde_json::{json, Value};
use sha2::Digest;
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    sync::mpsc,
    time::{Duration, Instant},
};

pub enum Flow {
    Device {
        tenant: String,
        client_id: String,
    },
    App {
        tenant: String,
        client_id: String,
        secret: String,
    },
    ServiceAccount {
        client_email: String,
        private_key_id: Option<String>,
        project_id: Option<String>,
        pkcs8_der: Vec<u8>,
        mailbox: String,
    },
    Installed {
        auth_url: String,
        client_id: String,
        client_secret: String,
    },
    Token(String),
}

pub struct Auth {
    flow: Flow,
    token_url: String,
    scope: String,
    access: String,
    refresh: Option<String>,
    expires: Option<Instant>,
    pub renewals: u32,
}

/// URL-safe base64 without padding (RFC 4648 §5)
pub fn b64url(data: &[u8]) -> String {
    crate::mail::client::base64(data)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// Base64 in either alphabet, padding optional
pub fn b64decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32)
    };
    let clean: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let clean = clean
        .strip_suffix(b"==")
        .or_else(|| clean.strip_suffix(b"="))
        .unwrap_or(&clean);
    if clean.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Decode a PEM block (`-----BEGIN PRIVATE KEY-----`) to DER bytes
pub fn pem_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    if body.is_empty() {
        return None;
    }
    b64decode(&body)
}

/// Build and sign an RS256 JWT assertion with a PKCS#8 RSA private key
pub fn sign_rs256_jwt(pkcs8_der: &[u8], key_id: Option<&str>, claims: &Value) -> Result<String> {
    let key_pair = RsaKeyPair::from_pkcs8(pkcs8_der)
        .map_err(|_| anyhow::anyhow!("invalid PKCS#8 RSA private_key"))?;
    let header = match key_id {
        Some(kid) if !kid.is_empty() => json!({ "alg": "RS256", "typ": "JWT", "kid": kid }),
        _ => json!({ "alg": "RS256", "typ": "JWT" }),
    };
    let signing_input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes())
    );
    let rng = SystemRandom::new();
    let mut sig = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(&RSA_PKCS1_SHA256, &rng, signing_input.as_bytes(), &mut sig)
        .map_err(|_| anyhow::anyhow!("RSA-SHA256 signing failed"))?;
    Ok(format!("{signing_input}.{}", b64url(&sig)))
}

/// Percent-decoding for query parameters (`+` -> space, `%XX` -> byte)
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a request target or URL carries an OAuth redirect parameter (`state=` or `error=`)
pub fn has_auth_params(input: &str) -> bool {
    let no_frag = input.trim().split('#').next().unwrap_or("");
    let Some((_, query)) = no_frag.split_once('?') else {
        return false;
    };
    query.split('&').any(|pair| {
        let (k, _) = pair.split_once('=').unwrap_or((pair, ""));
        matches!(percent_decode(k).as_str(), "state" | "error")
    })
}

/// Extract and validate `code` and `state` from a loopback request target or
/// a redirect URL pasted on stdin
pub fn parse_auth_redirect(input: &str, expected_state: &str) -> Result<String> {
    let no_frag = input.trim().split('#').next().unwrap_or("");
    let query = no_frag.split_once('?').map_or(no_frag, |(_, q)| q);
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_desc = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = percent_decode(k);
        let v = percent_decode(v);
        match k.as_str() {
            "code" => code = Some(v),
            "state" => state = Some(v),
            "error" => error = Some(v),
            "error_description" => error_desc = Some(v),
            _ => {}
        }
    }
    if let Some(err) = error {
        bail!("sign-in refused: {err}: {}", error_desc.unwrap_or_default());
    }
    ensure!(
        state.as_deref() == Some(expected_state),
        "OAuth state mismatch in redirect URL"
    );
    let code = code
        .filter(|c| !c.is_empty())
        .context("redirect URL has no authorization code")?;
    Ok(code)
}

/// The claims of a JWT access token that say who and what it is for, or
/// `None` for an opaque token
pub fn token_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let claims: Value = serde_json::from_slice(&b64decode(payload)?).ok()?;
    let mut out = serde_json::Map::new();
    for k in [
        "tid",
        "oid",
        "sub",
        "email",
        "hd",
        "upn",
        "unique_name",
        "preferred_username",
        "appid",
        "azp",
        "app_displayname",
        "scp",
        "scope",
        "roles",
        "aud",
        "iss",
    ] {
        if let Some(v) = claims.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    for k in ["iat", "exp"] {
        if let Some(t) = claims.get(k).and_then(Value::as_u64) {
            out.insert(k.into(), json!(dfcore::host::rfc3339_utc(t)));
        }
    }
    Some(Value::Object(out))
}

fn token_request(http: &mut Client, url: &str, pairs: &[(&str, &str)]) -> Result<(u16, Value)> {
    let body = form(pairs);
    let resp = http.request(
        "POST",
        url,
        &[("Accept", "application/json")],
        Some(("application/x-www-form-urlencoded", body.as_bytes())),
    )?;
    let status = resp.status;
    if status != 200 && status != 400 && status != 401 {
        bail!("{url}: HTTP {status}: {}", resp.error_text());
    }
    Ok((status, resp.json()?))
}

fn error_of(v: &Value) -> String {
    format!(
        "{}: {}",
        v["error"].as_str().unwrap_or("?"),
        v["error_description"]
            .as_str()
            .unwrap_or_default()
            .lines()
            .next()
            .unwrap_or_default()
    )
}

impl Auth {
    /// Sign in. `login` is the identity platform (https://login.microsoftonline.com),
    /// `graph` the Graph endpoint the token is for, `delegated` the permissions
    /// a device-code sign-in asks for (application sign-ins get `.default`).
    pub fn sign_in(
        http: &mut Client,
        flow: Flow,
        login: &str,
        graph: &str,
        delegated: &[&str],
    ) -> Result<(Self, Value)> {
        let login = login.trim_end_matches('/');
        let graph = graph.trim_end_matches('/');
        let (tenant, scope) = match &flow {
            Flow::Device { tenant, .. } => {
                let mut scopes: Vec<String> =
                    delegated.iter().map(|s| format!("{graph}/{s}")).collect();
                scopes.push("offline_access".into());
                (tenant.clone(), scopes.join(" "))
            }
            Flow::App { tenant, .. } => (tenant.clone(), format!("{graph}/.default")),
            Flow::Token(_) | Flow::ServiceAccount { .. } | Flow::Installed { .. } => {
                (String::new(), String::new())
            }
        };
        let token_url = format!("{login}/{}/oauth2/v2.0/token", crate::http::encode(&tenant));
        let mut auth = Auth {
            flow,
            token_url,
            scope,
            access: String::new(),
            refresh: None,
            expires: None,
            renewals: 0,
        };
        let record = match &auth.flow {
            Flow::Token(t) => {
                auth.access = t.clone();
                json!({ "method": "access token from a file", "claims": token_claims(t) })
            }
            Flow::App { client_id, .. } => {
                let client_id = client_id.clone();
                let granted = auth.renew_inner(http)?;
                json!({
                    "method": "client credentials (application permission)",
                    "client_id": client_id,
                    "tenant": tenant,
                    "scope_requested": auth.scope,
                    "scope_granted": granted,
                    "claims": token_claims(&auth.access),
                })
            }
            Flow::Device { client_id, .. } => {
                let client_id = client_id.clone();
                let granted = auth.device(http, login, &tenant, &client_id)?;
                json!({
                    "method": "device code (delegated)",
                    "client_id": client_id,
                    "tenant": tenant,
                    "scope_requested": auth.scope,
                    "scope_granted": granted,
                    "claims": token_claims(&auth.access),
                })
            }
            Flow::ServiceAccount { .. } | Flow::Installed { .. } => {
                bail!("use sign_in_google for Google OAuth flows")
            }
        };
        Ok((auth, record))
    }

    /// Sign in to Google APIs (`token`, `service-account`, or `installed`).
    pub fn sign_in_google(
        http: &mut Client,
        flow: Flow,
        token_url: &str,
        scope: &str,
    ) -> Result<(Self, Value)> {
        let mut auth = Auth {
            flow,
            token_url: token_url.to_string(),
            scope: scope.to_string(),
            access: String::new(),
            refresh: None,
            expires: None,
            renewals: 0,
        };
        let record = match &auth.flow {
            Flow::Token(t) => {
                auth.access = t.clone();
                json!({ "method": "access token from a file", "claims": token_claims(t) })
            }
            Flow::ServiceAccount {
                client_email,
                private_key_id,
                project_id,
                mailbox,
                ..
            } => {
                let client_email = client_email.clone();
                let private_key_id = private_key_id.clone();
                let project_id = project_id.clone();
                let mailbox = mailbox.clone();
                let granted = auth.renew_inner(http)?;
                json!({
                    "method": "service account (domain-wide delegation)",
                    "client_email": client_email,
                    "private_key_id": private_key_id,
                    "project_id": project_id,
                    "subject": mailbox,
                    "scope_requested": auth.scope,
                    "scope_granted": granted,
                    "claims": token_claims(&auth.access),
                })
            }
            Flow::Installed {
                auth_url,
                client_id,
                client_secret,
            } => {
                let auth_url = auth_url.clone();
                let client_id = client_id.clone();
                let client_secret = client_secret.clone();
                let granted = auth.installed(http, &auth_url, &client_id, &client_secret)?;
                json!({
                    "method": "installed application (OAuth 2.0 authorization code with PKCE)",
                    "client_id": client_id,
                    "scope_requested": auth.scope,
                    "scope_granted": granted,
                    "claims": token_claims(&auth.access),
                })
            }
            Flow::Device { .. } | Flow::App { .. } => {
                bail!("use sign_in for Microsoft Graph flows")
            }
        };
        Ok((auth, record))
    }

    fn take(&mut self, v: &Value) -> Result<Option<String>> {
        self.access = v["access_token"]
            .as_str()
            .context("the token response has no access_token")?
            .to_string();
        if let Some(r) = v["refresh_token"].as_str() {
            self.refresh = Some(r.to_string());
        }
        self.expires = v["expires_in"]
            .as_u64()
            .or_else(|| v["expires_in"].as_str().and_then(|s| s.parse().ok()))
            .map(|s| Instant::now() + Duration::from_secs(s));
        Ok(v["scope"].as_str().map(str::to_string))
    }

    fn installed(
        &mut self,
        http: &mut Client,
        auth_url: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Option<String>> {
        let rng = SystemRandom::new();
        let mut vbytes = [0u8; 32];
        let mut sbytes = [0u8; 16];
        rng.fill(&mut vbytes)
            .map_err(|_| anyhow::anyhow!("random generator failed"))?;
        rng.fill(&mut sbytes)
            .map_err(|_| anyhow::anyhow!("random generator failed"))?;
        let verifier = b64url(&vbytes);
        let challenge = b64url(&sha2::Sha256::digest(verifier.as_bytes()));
        let state = b64url(&sbytes);

        let listener = TcpListener::bind("127.0.0.1:0")
            .context("cannot bind loopback listener on 127.0.0.1")?;
        let port = listener.local_addr()?.port();
        let redirect_uri = format!("http://127.0.0.1:{port}");
        let query = form(&[
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", &redirect_uri),
            ("scope", &self.scope),
            ("state", &state),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("access_type", "offline"),
            ("prompt", "consent"),
        ]);
        let full_url = format!("{}?{query}", auth_url.trim_end_matches('?'));
        eprintln!("[!] Signing in can notify the account holder (new sign-in / third-party access alerts).");
        eprintln!("[?] Open this URL in a browser (or on another device and paste the redirect URL here):");
        eprintln!("{full_url}");

        let (tx, rx) = mpsc::channel::<Result<String>>();
        let tx_tcp = tx.clone();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                let mut req_line = String::new();
                {
                    let mut reader = BufReader::new(&mut stream);
                    let _ = reader.read_line(&mut req_line);
                }
                let target = req_line.split_whitespace().nth(1).unwrap_or("").to_string();
                let is_redirect = has_auth_params(&target);
                let (status, body): (&str, &[u8]) = if is_redirect {
                    (
                        "200 OK",
                        b"Sign-in received. You may close this browser tab.\n",
                    )
                } else {
                    ("404 Not Found", b"Waiting for OAuth redirect.\n")
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
                if is_redirect {
                    let _ = tx_tcp.send(Ok(target));
                    break;
                }
            }
        });
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut line = String::new();
            loop {
                line.clear();
                match stdin.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            let _ = tx.send(Ok(trimmed.to_string()));
                            break;
                        }
                    }
                }
            }
        });

        let received = rx
            .recv_timeout(Duration::from_secs(900))
            .context("timed out waiting for the OAuth redirect or pasted URL")??;
        let code = parse_auth_redirect(&received, &state)?;

        let url = self.token_url.clone();
        let (status, v) = token_request(
            http,
            &url,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("redirect_uri", &redirect_uri),
                ("code_verifier", &verifier),
            ],
        )?;
        if status != 200 {
            bail!("token request refused: {}", error_of(&v));
        }
        self.take(&v)
    }

    fn device(
        &mut self,
        http: &mut Client,
        login: &str,
        tenant: &str,
        client_id: &str,
    ) -> Result<Option<String>> {
        let url = format!(
            "{login}/{}/oauth2/v2.0/devicecode",
            crate::http::encode(tenant)
        );
        let (status, v) = token_request(
            http,
            &url,
            &[("client_id", client_id), ("scope", &self.scope)],
        )?;
        if status != 200 {
            bail!("device code request refused: {}", error_of(&v));
        }
        let device_code = v["device_code"]
            .as_str()
            .context("no device_code")?
            .to_string();
        let message = v["message"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "Open {} and enter the code {}",
                    v["verification_uri"].as_str().unwrap_or("?"),
                    v["user_code"].as_str().unwrap_or("?")
                )
            });
        eprintln!("[!] Signing in can notify the account holder (new sign-in alerts).");
        eprintln!("[?] {message}");
        let mut interval = v["interval"].as_u64().unwrap_or(5).max(1);
        let deadline =
            Instant::now() + Duration::from_secs(v["expires_in"].as_u64().unwrap_or(900));
        loop {
            std::thread::sleep(Duration::from_secs(interval));
            if Instant::now() > deadline {
                bail!("the device code expired before the sign-in was completed");
            }
            let (status, v) = token_request(
                http,
                &self.token_url.clone(),
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("client_id", client_id),
                    ("device_code", &device_code),
                ],
            )?;
            if status == 200 {
                return self.take(&v);
            }
            match v["error"].as_str() {
                Some("authorization_pending") => {}
                Some("slow_down") => interval += 5,
                _ => bail!("sign-in failed: {}", error_of(&v)),
            }
        }
    }

    fn renew_inner(&mut self, http: &mut Client) -> Result<Option<String>> {
        let url = self.token_url.clone();
        let (status, v) =
            match &self.flow {
                Flow::App {
                    client_id, secret, ..
                } => token_request(
                    http,
                    &url,
                    &[
                        ("grant_type", "client_credentials"),
                        ("client_id", client_id),
                        ("client_secret", secret),
                        ("scope", &self.scope),
                    ],
                )?,
                Flow::Device { client_id, .. } => {
                    let refresh = self.refresh.clone().context(
                        "the token expired and there is no refresh token; sign in again",
                    )?;
                    token_request(
                        http,
                        &url,
                        &[
                            ("grant_type", "refresh_token"),
                            ("client_id", client_id),
                            ("refresh_token", &refresh),
                            ("scope", &self.scope),
                        ],
                    )?
                }
                Flow::ServiceAccount {
                    client_email,
                    private_key_id,
                    pkcs8_der,
                    mailbox,
                    ..
                } => {
                    let now = dfcore::host::unix_now();
                    let claims = json!({
                        "iss": client_email,
                        "sub": mailbox,
                        "scope": &self.scope,
                        "aud": &url,
                        "iat": now,
                        "exp": now + 3600,
                    });
                    let assertion = sign_rs256_jwt(pkcs8_der, private_key_id.as_deref(), &claims)?;
                    token_request(
                        http,
                        &url,
                        &[
                            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                            ("assertion", &assertion),
                        ],
                    )?
                }
                Flow::Installed {
                    client_id,
                    client_secret,
                    ..
                } => {
                    let refresh = self.refresh.clone().context(
                        "the token expired and there is no refresh token; sign in again",
                    )?;
                    token_request(
                        http,
                        &url,
                        &[
                            ("grant_type", "refresh_token"),
                            ("client_id", client_id),
                            ("client_secret", client_secret),
                            ("refresh_token", &refresh),
                        ],
                    )?
                }
                Flow::Token(_) => {
                    bail!("the access token from the file expired or was refused; get a new one")
                }
            };
        if status != 200 {
            bail!("token request refused: {}", error_of(&v));
        }
        self.take(&v)
    }

    /// Get a new access token (after a 401, or before expiry).
    pub fn renew(&mut self, http: &mut Client) -> Result<()> {
        self.renew_inner(http)?;
        self.renewals += 1;
        Ok(())
    }

    /// The access token, renewed when it has less than five minutes left
    pub fn bearer(&mut self, http: &mut Client) -> Result<String> {
        if self
            .expires
            .is_some_and(|e| e.saturating_duration_since(Instant::now()) < Duration::from_secs(300))
        {
            self.renew(http)?;
        }
        Ok(format!("Bearer {}", self.access))
    }

    pub fn can_renew(&self) -> bool {
        !matches!(self.flow, Flow::Token(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_both_alphabets() {
        assert_eq!(b64decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(b64decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(b64decode("Zm9vYg").unwrap(), b"foob");
        assert_eq!(b64decode("-_8").unwrap(), [0xfb, 0xff]);
        assert_eq!(b64decode("+/8=").unwrap(), [0xfb, 0xff]);
        assert!(b64decode("Zm9v!").is_none());
        assert!(b64decode("Z").is_none());
    }

    #[test]
    fn claims_of_a_token() {
        let payload = r#"{"tid":"t1","upn":"alice@example.org","scp":"Mail.Read","exp":1800000000,"secret_stuff":1}"#;
        let token = format!("{}.{}.sig", b64url(b"{}"), b64url(payload.as_bytes()));
        let c = token_claims(&token).unwrap();
        assert_eq!(c["upn"], "alice@example.org");
        assert_eq!(c["exp"], "2027-01-15T08:00:00Z");
        assert!(c.get("secret_stuff").is_none());
        assert!(token_claims("opaque-token").is_none());
    }

    #[test]
    fn redirect_url_parsing_and_state_check() {
        assert!(!has_auth_params(""));
        assert!(!has_auth_params("/"));
        assert!(!has_auth_params("/favicon.ico"));
        assert!(!has_auth_params("/?foo=bar"));
        assert!(has_auth_params("/?code=ok&state=st123"));
        assert!(has_auth_params("/?error=access_denied"));
        let code = parse_auth_redirect(
            "http://127.0.0.1:43210/?state=st123&code=4%2F0Abc-xyz&scope=email#frag",
            "st123",
        )
        .unwrap();
        assert_eq!(code, "4/0Abc-xyz");
        assert_eq!(
            parse_auth_redirect("/?code=ok&state=st123", "st123").unwrap(),
            "ok"
        );
        assert!(parse_auth_redirect("/?code=ok&state=wrong", "st123").is_err());
        assert!(parse_auth_redirect("/?error=access_denied&state=st123", "st123").is_err());
    }
}
