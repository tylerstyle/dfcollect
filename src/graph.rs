//! `dfcollect graph`: a Microsoft 365 (Exchange Online) mailbox through
//! Microsoft Graph, read-only by API.
//!
//! - Only GET requests go to Graph (the sign-in POSTs go to the identity
//!   platform). Nothing in the mailbox changes, `isRead` included.
//! - All folders, hidden ones too, and the Recoverable Items deletions
//!   folder. Search folders are skipped (they only point at other folders).
//! - Every message's metadata is listed first; the scope (folder,
//!   receivedDateTime) is decided before its body is fetched.
//! - The body is Exchange's MIME rendition (`/messages/{id}/$value`), stored
//!   as `<folder>/<received>-<id hash>.eml`, with Graph's metadata in the
//!   item. Exchange converts the stored item to MIME, so the bytes need not be
//!   those once received; the manifest says so.
//! - Ids are immutable ids, stable when a message moves.
//! - On the tenant's side the sign-in is logged, and Exchange may log
//!   MailItemsAccessed in the Unified Audit Log.

use crate::{
    args::{GraphArgs, GraphConnArgs},
    common,
    container::{Container, CopyError, Hasher},
    files::CONTAINER,
    http::{encode, strip_query, Client, Response},
    mail::{client::sha256_hex, first_line, folder_scope, prompt_secret},
    meta::Stamps,
    oauth::{Auth, Flow},
    scope, Usage, TOOL, VERSION,
};
use anyhow::{bail, Context, Result};
use dfcore::manifest::{
    Candidate, Collection, Completion, Decision, FootprintEntry, Header, Item, ItemStatus, Method,
    ScopeRules, Source, Times,
};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

const AUDIT_ACTION: &str = "mail_acquisition";
const TIME_BASIS: &str = "receivedDateTime";
const PAGE: u32 = 100;
/// Message properties kept in each item
const SELECT: &str = "id,internetMessageId,conversationId,parentFolderId,receivedDateTime,\
sentDateTime,createdDateTime,lastModifiedDateTime,subject,from,sender,toRecipients,ccRecipients,\
bccRecipients,replyTo,isRead,isDraft,hasAttachments,importance,flag,categories,changeKey";
/// PR_MESSAGE_SIZE, the size Exchange keeps for the item
const SIZE_PROPERTY: &str = "Integer 0x0E08";

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum GraphAuth {
    /// Sign in as the account with a device code (delegated Mail.Read)
    Device,
    /// Client credentials: application permission Mail.Read, with the tenant's cooperation
    App,
    /// An access token from --token-file
    Token,
}

pub struct Outcome {
    pub code: u8,
    pub summary: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Folder {
    id: String,
    path: String,
    total: Option<u64>,
    hidden: bool,
}

/// A folder's display name as one path level (`/` inside a name escaped)
fn level(name: &str) -> String {
    name.replace('%', "%25").replace('/', "%2F")
}

/// `<folder>/<received, compact UTC>-<first 12 hex of SHA-256(id)>`
fn item_path(folder: &str, received: &str, id: &str) -> String {
    let compact: String = received
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(15)
        .collect();
    format!("{folder}/{compact}Z-{}", &sha256_hex(id.as_bytes())[..12])
}

/// `me` or `users/<id>`
fn who(mailbox: &str) -> String {
    if mailbox.eq_ignore_ascii_case("me") {
        "me".into()
    } else {
        format!("users/{}", encode(mailbox))
    }
}

/// Requests to Graph with a bearer token: a refused token is renewed once,
/// and URLs outside the Graph endpoint (a crafted nextLink) never get it.
pub(crate) struct Api {
    pub http: Client,
    pub auth: Auth,
    pub graph: String,
}

impl Api {
    fn send(
        &mut self,
        method: &str,
        url: &str,
        accept: &str,
        body: Option<&Value>,
    ) -> Result<Response> {
        if !url.starts_with(&format!("{}/", self.graph)) {
            bail!("refusing to send the token to {}", strip_query(url));
        }
        let data = body.map(|b| b.to_string());
        let mut renewed = false;
        loop {
            let bearer = self.auth.bearer(&mut self.http)?;
            let resp = self.http.request(
                method,
                url,
                &[
                    ("Authorization", &bearer),
                    ("Accept", accept),
                    ("Prefer", "IdType=\"ImmutableId\""),
                ],
                data.as_deref().map(|d| ("application/json", d.as_bytes())),
            )?;
            if resp.status == 401 && !renewed && self.auth.can_renew() {
                self.auth.renew(&mut self.http)?;
                renewed = true;
                continue;
            }
            return Ok(resp);
        }
    }

    pub fn get(&mut self, url: &str, accept: &str) -> Result<Response> {
        self.send("GET", url, accept, None)
    }

    fn json_of(&self, method: &str, url: &str, resp: Response, ok: &[u16]) -> Result<Value> {
        if !ok.contains(&resp.status) {
            bail!(
                "{method} {}: HTTP {}: {}",
                strip_query(url.get(self.graph.len()..).unwrap_or(url)),
                resp.status,
                resp.error_text()
            );
        }
        resp.json()
    }

    pub fn get_json(&mut self, url: &str) -> Result<Value> {
        let resp = self.get(url, "application/json")?;
        self.json_of("GET", url, resp, &[200])
    }

    /// A POST with a JSON body (m365-logs creates an audit log query)
    pub fn post_json(&mut self, url: &str, body: &Value) -> Result<Value> {
        let resp = self.send("POST", url, "application/json", Some(body))?;
        self.json_of("POST", url, resp, &[200, 201, 202])
    }

    /// All pages of a collection
    pub fn pages(&mut self, first: &str, stop: &AtomicBool) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        self.each_page(first, stop, |page| {
            out.extend(page.iter().cloned());
            Ok(())
        })?;
        Ok(out)
    }

    /// Every page of a collection, handed over as it arrives
    pub fn each_page(
        &mut self,
        first: &str,
        stop: &AtomicBool,
        mut f: impl FnMut(&[Value]) -> Result<()>,
    ) -> Result<u64> {
        let mut next = Some(first.to_string());
        let mut pages = 0;
        while let Some(url) = next {
            if stop.load(Ordering::Relaxed) {
                bail!("stopped by a signal");
            }
            let v = self.get_json(&url)?;
            if let Some(items) = v["value"].as_array() {
                f(items)?;
            }
            pages += 1;
            next = v["@odata.nextLink"].as_str().map(str::to_string);
        }
        Ok(pages)
    }
}

struct Session<'a> {
    args: &'a GraphArgs,
    api: Api,
    base: String,
    account: String,
    rules: ScopeRules,
    collection: Collection,
    container: Container,
    stop: &'a AtomicBool,
    folders_listed: u64,
    bodies: u64,
}

impl Session<'_> {
    fn pages(&mut self, first: &str) -> Result<Vec<Value>> {
        self.api.pages(first, self.stop)
    }

    fn walk(&mut self, url: &str, parent: &str, out: &mut Vec<Folder>) -> Result<()> {
        for f in self.pages(url)? {
            let id = f["id"].as_str().context("a folder without id")?.to_string();
            let name = level(f["displayName"].as_str().unwrap_or("(no name)"));
            let path = if parent.is_empty() {
                name
            } else {
                format!("{parent}/{name}")
            };
            if f["@odata.type"].as_str() == Some("#microsoft.graph.mailSearchFolder") {
                continue;
            }
            let children = f["childFolderCount"].as_u64().unwrap_or(0);
            out.push(Folder {
                id: id.clone(),
                path: path.clone(),
                total: f["totalItemCount"].as_u64(),
                hidden: f["isHidden"].as_bool().unwrap_or(false),
            });
            if children > 0 {
                let url = format!(
                    "{}/mailFolders/{}/childFolders?includeHiddenFolders=true&$top={PAGE}",
                    self.base,
                    encode(&id)
                );
                self.walk(&url, &path, out)?;
            }
        }
        Ok(())
    }

    fn folders(&mut self) -> Result<Vec<Folder>> {
        let mut out = Vec::new();
        let url = format!(
            "{}/mailFolders?includeHiddenFolders=true&$top={PAGE}",
            self.base
        );
        self.walk(&url, "", &mut out)?;
        // Soft-deleted items live outside the folder tree
        let url = format!("{}/mailFolders/recoverableitemsdeletions", self.base);
        let resp = self.api.get(&url, "application/json")?;
        let recoverable = match resp.status {
            200 => {
                let f = resp.json()?;
                let id = f["id"].as_str().context("a folder without id")?.to_string();
                if !out.iter().any(|x| x.id == id) {
                    out.push(Folder {
                        id,
                        path: "Recoverable Items/Deletions".into(),
                        total: f["totalItemCount"].as_u64(),
                        hidden: true,
                    });
                }
                json!("listed")
            }
            s => json!(format!("not available: HTTP {s}: {}", resp.error_text())),
        };
        out.sort_by(|a, b| a.path.cmp(&b.path));
        self.collection.footprint(FootprintEntry::new(
            "request",
            json!({
                "request": "GET mailFolders (all levels, hidden folders included)",
                "folders": out.iter().map(|f| json!({ "path": f.path, "items": f.total, "hidden": f.hidden })).collect::<Vec<_>>(),
                "recoverable_items_deletions": recoverable,
            }),
        ))?;
        Ok(out)
    }

    fn folder(&mut self, folder: &Folder) -> Result<()> {
        if let Some(reason) = folder_scope(&self.rules, &folder.path) {
            self.collection.count_out_of_scope(&reason);
            return Ok(());
        }
        self.folders_listed += 1;
        if folder.total == Some(0) {
            return Ok(());
        }
        let url = format!(
            "{}/mailFolders/{}/messages?$top={PAGE}&$select={}&$expand={}",
            self.base,
            encode(&folder.id),
            encode(SELECT),
            encode(&format!(
                "singleValueExtendedProperties($filter=id eq '{SIZE_PROPERTY}')"
            ))
        );
        let messages = self.pages(&url)?;
        self.collection.footprint(FootprintEntry::new(
            "request",
            json!({ "request": "GET messages (metadata)", "folder": folder.path, "messages": messages.len() }),
        ))?;
        for m in &messages {
            if self.stop.load(Ordering::Relaxed) {
                bail!("stopped by a signal");
            }
            self.message(folder, m)?;
        }
        Ok(())
    }

    fn message(&mut self, folder: &Folder, m: &Value) -> Result<()> {
        let id = m["id"].as_str().context("a message without id")?;
        let received = m[TIME_BASIS].as_str().unwrap_or_default();
        let ns = dfcore::host::parse_rfc3339(received).ok();
        let path = item_path(&folder.path, received, id);
        let mapi_size = m["singleValueExtendedProperties"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|p| p["value"].as_str())
            .and_then(|v| v.parse::<u64>().ok());
        let mut metadata = m.clone();
        if let Some(o) = metadata.as_object_mut() {
            o.remove("singleValueExtendedProperties");
            o.remove("@odata.etag");
            o.insert("folder".into(), json!(folder.path));
            o.insert("exchange_size".into(), json!(mapi_size));
        }
        let times = Times {
            modified: m[TIME_BASIS].as_str().map(str::to_string),
            birth: m["createdDateTime"].as_str().map(str::to_string),
            ..Times::default()
        };
        match self.rules.decide(&Candidate {
            path: &path,
            account: Some(&self.account),
            time_ns: ns,
        }) {
            Decision::InScope => {}
            Decision::OutOfScope(reason) => {
                if self.args.scope.list_out_of_scope {
                    let mut item = Item::out_of_scope(path, reason);
                    item.kind = Some("message".into());
                    item.account = Some(self.account.clone());
                    item.times = times;
                    item.metadata = metadata;
                    self.collection.add(item)?;
                } else {
                    self.collection.count_out_of_scope(&reason);
                }
                return Ok(());
            }
        }
        let url = format!("{}/messages/{}/$value", self.base, encode(id));
        let resp = self.api.get(&url, "*/*")?;
        if resp.status != 200 {
            let mut item = Item::new(ItemStatus::Error, path);
            item.kind = Some("message".into());
            item.account = Some(self.account.clone());
            item.reason = Some(format!(
                "GET $value: HTTP {}: {}",
                resp.status,
                resp.error_text()
            ));
            item.times = times;
            item.metadata = metadata;
            self.collection.add(item)?;
            return Ok(());
        }
        let member = format!("{path}.eml");
        let ns = ns.unwrap_or(0);
        let stamps = Stamps {
            modified: ns,
            accessed: ns,
            changed: ns,
            birth: None,
        };
        let mut hasher = Hasher::new(self.args.md5, self.args.sha1);
        match self
            .container
            .add_file(&member, 0o644, &stamps, &mut &resp.body[..], &mut hasher)
        {
            Ok(_) => {}
            Err(CopyError::Container(e)) => return Err(e),
            Err(CopyError::Source(e)) => return Err(e.into()),
            Err(CopyError::Duplicate(name)) => {
                let mut item = Item::new(ItemStatus::Error, path);
                item.kind = Some("message".into());
                item.account = Some(self.account.clone());
                item.reason = Some(format!(
                    "another message already has the container name {name}"
                ));
                item.metadata = metadata;
                self.collection.add(item)?;
                return Ok(());
            }
        }
        self.bodies += 1;
        let mut item = Item::new(ItemStatus::Acquired, path);
        item.kind = Some("message".into());
        item.account = Some(self.account.clone());
        item.stored_as = Some(CONTAINER.into());
        item.member = Some(member);
        item.size = Some(resp.body.len() as u64);
        item.hashes = hasher.finish();
        item.times = times;
        item.metadata = metadata;
        self.collection.add(item)?;
        Ok(())
    }
}

/// The TLS sessions, with each host's certificates written to `tls/`
pub(crate) fn tls_records(dir: &Path, http: &Client) -> Result<Value> {
    std::fs::create_dir_all(dir.join("tls"))?;
    let mut out = serde_json::Map::new();
    for (host, tls) in &http.tls {
        let mut chain = Vec::new();
        for (i, der) in tls.chain.iter().enumerate() {
            let file = format!("tls/{}-certificate-{i}.der", host.replace([':', '/'], "_"));
            std::fs::write(dir.join(&file), der).with_context(|| format!("Cannot write {file}"))?;
            chain.push(json!({ "sha256": sha256_hex(der), "file": file }));
        }
        out.insert(
            host.clone(),
            json!({ "version": tls.version, "cipher": tls.cipher, "verified_by": tls.verified_by, "chain": chain }),
        );
    }
    Ok(Value::Object(out))
}

fn header(args: &GraphArgs, scope: dfcore::manifest::Scope) -> Result<Header> {
    let graph = args.conn.graph_endpoint.trim_end_matches('/');
    Ok(Header {
        action: AUDIT_ACTION.into(),
        case: common::case(&args.case),
        source: Source {
            kind: "microsoft-graph".into(),
            locator: format!("{graph}/v1.0/{}", who(&args.mailbox)),
            identity: Value::Null,
            details: Value::Null,
        },
        method: Method {
            tool: TOOL.into(),
            tool_version: VERSION.into(),
            system_revision: dfcore::release::system_revision(),
            argv: std::env::args().collect(),
            read_only_primitives: vec![
                "Microsoft Graph: GET requests only; nothing is created, changed or deleted in the mailbox".into(),
                "GET /messages/{id}/$value does not change isRead".into(),
            ],
            description: Some(format!(
                "Folders listed through Graph (hidden folders and Recoverable Items deletions included, search \
                 folders skipped); each folder's message metadata fetched first and every message decided by the \
                 scope (folder, {TIME_BASIS}) before its body is fetched; bodies are Exchange's MIME rendition \
                 (GET /messages/{{id}}/$value), which Exchange converts from the stored item and which need not be \
                 the bytes once received; stored as <folder>/<received>-<id hash>.eml in {CONTAINER}, with Graph's \
                 metadata (immutable ids) in each item; the container is read back and every member hashed again"
            )),
        },
        scope,
        clocks: dfcore::manifest::Clocks {
            reference: common::reference(&args.clock)?,
            ..Default::default()
        },
    })
}

/// The sign-in the connection options ask for
pub(crate) fn flow(conn: &GraphConnArgs) -> Result<Flow> {
    let client_id = || {
        conn.client_id.clone().ok_or_else(|| {
            Usage(
                "--client-id is required: the application (client) id of your app registration"
                    .into(),
            )
        })
    };
    Ok(match conn.auth {
        GraphAuth::Token => {
            let path = conn
                .token_file
                .as_ref()
                .ok_or_else(|| Usage("--auth token needs --token-file".into()))?;
            Flow::Token(first_line(path)?)
        }
        GraphAuth::Device => Flow::Device {
            tenant: conn.tenant.clone(),
            client_id: client_id()?,
        },
        GraphAuth::App => {
            if conn.tenant.eq_ignore_ascii_case("organizations")
                || conn.tenant.eq_ignore_ascii_case("common")
            {
                return Err(Usage(
                    "--auth app needs the tenant: --tenant <tenant id or domain>".into(),
                )
                .into());
            }
            let secret = match &conn.client_secret_file {
                Some(p) => first_line(p)?,
                None => prompt_secret("Client secret: ")?,
            };
            Flow::App {
                tenant: conn.tenant.clone(),
                client_id: client_id()?,
                secret,
            }
        }
    })
}

/// Both endpoints must be https URLs
pub(crate) fn check_endpoints(conn: &GraphConnArgs) -> Result<()> {
    for (name, url) in [
        ("--graph-endpoint", &conn.graph_endpoint),
        ("--login-endpoint", &conn.login_endpoint),
    ] {
        crate::http::parse_url(url).map_err(|e| Usage(format!("{name}: {e:#}")))?;
    }
    Ok(())
}

pub fn run(args: &GraphArgs, stop: &AtomicBool) -> Result<Outcome> {
    let mut scope = scope::build(&args.scope)?;
    if scope.not_before.is_some() || scope.not_after.is_some() {
        if args.scope.scope.is_none() {
            scope.time_basis = Some(TIME_BASIS.into());
        } else if !scope
            .time_basis
            .as_deref()
            .is_some_and(|b| b.eq_ignore_ascii_case(TIME_BASIS))
        {
            return Err(Usage(format!(
                "a Graph scope's time window applies to {TIME_BASIS}; set \"time_basis\": \"{TIME_BASIS}\""
            ))
            .into());
        }
    }
    let rules = scope.rules().map_err(|e| Usage(format!("{e:#}")))?;
    check_endpoints(&args.conn)?;
    if args.conn.auth == GraphAuth::App && args.mailbox.eq_ignore_ascii_case("me") {
        return Err(
            Usage("--auth app reads a named mailbox: give --mailbox <user@domain>".into()).into(),
        );
    }
    let (output, _) = common::check_output(&args.output, args.allow_tmpfs)?;
    let flow = flow(&args.conn)?;
    let graph = args.conn.graph_endpoint.trim_end_matches('/').to_string();
    let accounts = scope.accounts.clone();

    let mut collection = Collection::create(&output, header(args, scope)?)?;
    let container = match Container::create(&output.join(CONTAINER), args.compress) {
        Ok(c) => c,
        Err(e) => {
            collection.finish(Completion::Aborted {
                reason: format!("{e:#}"),
            })?;
            return Err(e);
        }
    };
    let mut http = Client::new(Duration::from_secs(args.conn.timeout));
    let (auth, record) = match Auth::sign_in(
        &mut http,
        flow,
        &args.conn.login_endpoint,
        &graph,
        &["Mail.Read"],
    ) {
        Ok(a) => a,
        Err(e) => {
            let reason = format!("{e:#}");
            collection.footprint(FootprintEntry::new("auth", json!({ "error": reason })))?;
            container.finish()?;
            let (code, finished, _) = common::conclude(collection, &output, Some((reason, 4)))?;
            return Ok(Outcome {
                code,
                summary: summary(&output, &finished, 0, 0),
            });
        }
    };
    collection.footprint(FootprintEntry::new("auth", record.clone()))?;

    let mut session = Session {
        args,
        base: format!("{graph}/v1.0/{}", who(&args.mailbox)),
        api: Api { http, auth, graph },
        account: args.mailbox.clone(),
        rules,
        collection,
        container,
        stop,
        folders_listed: 0,
        bodies: 0,
    };
    let result = (|| -> Result<()> {
        let url = format!(
            "{}?$select=id,displayName,userPrincipalName,mail",
            session.base
        );
        let user = session.api.get_json(&url)?;
        if let Some(upn) = user["userPrincipalName"].as_str() {
            session.account = upn.to_string();
        }
        if !accounts.is_empty()
            && !accounts
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&session.account))
        {
            bail!(
                "the mailbox {} is not among the scope's accounts",
                session.account
            );
        }
        let tls = tls_records(&output, &session.api.http)?;
        session.collection.set_source_identity(json!({
            "user": user,
            "auth": record,
            "tls": tls,
        }))?;
        for folder in session.folders()? {
            if stop.load(Ordering::Relaxed) {
                bail!("stopped by a signal");
            }
            session.folder(&folder)?;
        }
        Ok(())
    })();
    let Session {
        mut collection,
        container,
        api: Api { http, auth, .. },
        folders_listed,
        bodies,
        ..
    } = session;
    collection.footprint(FootprintEntry {
        bytes_sent: Some(http.sent),
        bytes_received: Some(http.received),
        ..FootprintEntry::new(
            "disconnect",
            json!({
                "requests": http.requests,
                "throttled_waits": http.waits,
                "token_renewals": auth.renewals,
                "folders_listed": folders_listed,
                "bodies": bodies,
            }),
        )
    })?;
    let mut stopped = match result {
        Ok(()) => None,
        Err(e) if stop.load(Ordering::Relaxed) => Some((format!("{e:#}"), 8)),
        Err(e) => Some((format!("{e:#}"), 6)),
    };
    if let Err(e) = container.finish() {
        stopped.get_or_insert((format!("{e:#}"), 6));
    }
    let (code, finished, _) = common::conclude(collection, &output, stopped)?;
    Ok(Outcome {
        code,
        summary: summary(&output, &finished, folders_listed, bodies),
    })
}

fn summary(
    output: &Path,
    finished: &dfcore::manifest::Finished,
    folders: u64,
    bodies: u64,
) -> Value {
    let m = &finished.manifest;
    json!({
        "collection": output,
        "status": m.status,
        "folders_listed": folders,
        "messages": bodies,
        "bytes": m.totals.bytes,
        "out_of_scope_listed": m.totals.out_of_scope,
        "out_of_scope_counted": m.totals.unlisted_out_of_scope.values().sum::<u64>(),
        "errors": m.totals.errors,
        "problems": m.errors,
        "audit_anchor": m.audit_anchor,
        "warnings": finished.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_names() {
        assert_eq!(level("Kunden/Projekte"), "Kunden%2FProjekte");
        assert_eq!(level("100%"), "100%25");
        let p = item_path("Inbox", "2026-03-01T10:00:00Z", "AAMkAD=");
        assert!(p.starts_with("Inbox/20260301T100000Z-"), "{p}");
        assert_eq!(p.len(), "Inbox/20260301T100000Z-".len() + 12);
        assert_ne!(p, item_path("Inbox", "2026-03-01T10:00:00Z", "AAMkAE="));
        assert_eq!(who("me"), "me");
        assert_eq!(who("alice@example.org"), "users/alice%40example.org");
    }
}
