//! Sign-in to Microsoft Graph through the Microsoft identity platform:
//! - device code (delegated): the examiner signs in as the account holder on
//!   any device with a browser; scopes `Mail.Read` and `offline_access`, so the
//!   token is renewed during long acquisitions;
//! - client credentials (the application permission `Mail.Read`, granted by
//!   the tenant's admin): any mailbox of that tenant;
//! - an access token from a file, obtained some other way (not renewed).
//!
//! Tokens and secrets stay in memory. The record holds the method, client,
//! tenant, granted scopes and the claims in the token that name the account
//! and the app (read, not verified: the API verifies them).

use crate::http::{form, Client};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

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

/// The claims of a JWT access token that say who and what it is for, or
/// `None` for an opaque token
pub fn token_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let claims: Value = serde_json::from_slice(&b64decode(payload)?).ok()?;
    let mut out = serde_json::Map::new();
    for k in [
        "tid",
        "oid",
        "upn",
        "unique_name",
        "preferred_username",
        "appid",
        "azp",
        "app_displayname",
        "scp",
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
    /// `graph` the Graph endpoint the token is for.
    pub fn sign_in(
        http: &mut Client,
        flow: Flow,
        login: &str,
        graph: &str,
    ) -> Result<(Self, Value)> {
        let login = login.trim_end_matches('/');
        let graph = graph.trim_end_matches('/');
        let (tenant, scope) = match &flow {
            Flow::Device { tenant, .. } => {
                (tenant.clone(), format!("{graph}/Mail.Read offline_access"))
            }
            Flow::App { tenant, .. } => (tenant.clone(), format!("{graph}/.default")),
            Flow::Token(_) => (String::new(), String::new()),
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
        let (status, v) = match &self.flow {
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
                let refresh = self
                    .refresh
                    .clone()
                    .context("the token expired and there is no refresh token; sign in again")?;
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
        let enc = |b: &[u8]| {
            crate::mail::client::base64(b)
                .trim_end_matches('=')
                .replace('+', "-")
                .replace('/', "_")
        };
        let token = format!("{}.{}.sig", enc(b"{}"), enc(payload.as_bytes()));
        let c = token_claims(&token).unwrap();
        assert_eq!(c["upn"], "alice@example.org");
        assert_eq!(c["exp"], "2027-01-15T08:00:00Z");
        assert!(c.get("secret_stuff").is_none());
        assert!(token_claims("opaque-token").is_none());
    }
}
