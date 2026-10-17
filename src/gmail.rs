//! `dfcollect gmail`: a Google Workspace or Gmail mailbox through the Gmail
//! API, read-only by API design (`gmail.readonly`, `format=raw`).
//!
//! - Only GET requests go to the Gmail API (OAuth token requests go to the
//!   token endpoint). Scope `https://www.googleapis.com/auth/gmail.readonly`
//!   cannot modify messages, labels or flags (`UNREAD` included).
//! - All messages, including `SPAM` and `TRASH` (`includeSpamTrash=true`), are
//!   listed first by ID; for each ID, minimal metadata (`?format=minimal`:
//!   `labelIds`, `internalDate`, `sizeEstimate`, `threadId`, `historyId`) is
//!   fetched and decided against the scope before `?format=raw` is requested.
//! - Labels are not folders. Each in-scope message is stored once under its
//!   first label in the order `INBOX`, `SENT`, `DRAFT`, `SPAM`, `TRASH`, then
//!   user labels by name, else `All Mail`, as
//!   `<label>/<internalDate compact>Z-<id>.eml` in `data.zip`.
//! - Include and exclude patterns are matched against
//!   `<label>/<internalDate compact>Z-<id>` once for every label the message
//!   carries: excluded if any label path matches an exclude pattern, otherwise
//!   included if there are no includes or if any label path matches one.
//! - `?format=raw` returns the exact RFC 2822 message bytes (base64url-encoded
//!   in `raw`).
//! - On the tenant's side, Google Workspace logs OAuth token grants for
//!   service accounts in the Token Audit Log; an `installed` sign-in can send a
//!   "new sign-in" or "third-party access" alert to the account holder.

use crate::{
    args::GmailArgs,
    common::{self, Phase, RunCtx},
    console::{need_secret, SecretAsk},
    container::{Container, CopyError, Hasher},
    files::CONTAINER,
    graph::{tls_records, Api},
    http::{encode, Client},
    mail::first_line,
    meta::Stamps,
    oauth::{b64decode, pem_der, Auth, Flow},
    scope, Usage, TOOL, VERSION,
};
use anyhow::{bail, Context, Result};
use dfcore::manifest::{
    glob_match, Candidate, Collection, Completion, Decision, FootprintEntry, Header, Item,
    ItemStatus, Method, ScopeRules, Source, Times,
};
use ring::signature::RsaKeyPair;
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path, time::Duration};
use zeroize::Zeroizing;

const AUDIT_ACTION: &str = "mail_acquisition";
const TIME_BASIS: &str = "internalDate";
const GMAIL_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";
const PAGE: u32 = 500;

const PRIORITY_SYSTEM_LABELS: [&str; 5] = ["INBOX", "SENT", "DRAFT", "SPAM", "TRASH"];
const OTHER_SYSTEM_LABELS: [&str; 9] = [
    "UNREAD",
    "STARRED",
    "IMPORTANT",
    "CHAT",
    "CATEGORY_PERSONAL",
    "CATEGORY_SOCIAL",
    "CATEGORY_PROMOTIONS",
    "CATEGORY_UPDATES",
    "CATEGORY_FORUMS",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum GmailAuth {
    /// Sign in as the account holder with a Desktop app OAuth client (authorization code + PKCE)
    Installed,
    /// Google Workspace service account with domain-wide delegation (--key-file, --mailbox)
    ServiceAccount,
    /// An access token with gmail.readonly from --token-file
    Token,
}

pub struct Outcome {
    pub code: u8,
    pub summary: Value,
}

#[derive(Debug, Clone)]
struct LabelInfo {
    id: String,
    name: String,
    is_user: bool,
}

#[derive(Debug, Default)]
struct LabelMap {
    by_id: BTreeMap<String, LabelInfo>,
}

impl LabelMap {
    fn from_json(v: &Value) -> Self {
        let mut by_id = BTreeMap::new();
        if let Some(arr) = v["labels"].as_array() {
            for l in arr {
                let Some(id) = l["id"].as_str() else {
                    continue;
                };
                let name = l["name"].as_str().unwrap_or(id).to_string();
                let is_user = match l["type"].as_str() {
                    Some("user") => true,
                    Some("system") => false,
                    _ => {
                        !PRIORITY_SYSTEM_LABELS.contains(&id)
                            && !OTHER_SYSTEM_LABELS.contains(&id)
                            && !id.starts_with("CATEGORY_")
                    }
                };
                by_id.insert(
                    id.to_string(),
                    LabelInfo {
                        id: id.to_string(),
                        name,
                        is_user,
                    },
                );
            }
        }
        Self { by_id }
    }

    fn name_of<'a>(&'a self, id: &'a str) -> &'a str {
        self.by_id.get(id).map_or(id, |l| l.name.as_str())
    }

    fn is_user_label(&self, id: &str) -> bool {
        self.by_id.get(id).map_or_else(
            || {
                !PRIORITY_SYSTEM_LABELS.contains(&id)
                    && !OTHER_SYSTEM_LABELS.contains(&id)
                    && !id.starts_with("CATEGORY_")
            },
            |l| l.is_user,
        )
    }

    /// Choose the single storage label (`INBOX`, `SENT`, `DRAFT`, `SPAM`,
    /// `TRASH`, then user labels sorted by name, else `All Mail`) and resolve
    /// all labels on the message.
    fn resolve(&self, label_ids: &[String]) -> (String, Vec<String>, Vec<Value>) {
        let mut primary = None;
        for sys in PRIORITY_SYSTEM_LABELS {
            if label_ids
                .iter()
                .any(|id| id == sys || self.name_of(id) == sys)
            {
                primary = Some(sys.to_string());
                break;
            }
        }
        if primary.is_none() {
            let mut user_names: Vec<String> = label_ids
                .iter()
                .filter(|id| self.is_user_label(id))
                .map(|id| self.name_of(id).to_string())
                .collect();
            user_names.sort();
            primary = user_names.into_iter().next();
        }
        let primary = primary.unwrap_or_else(|| "All Mail".into());

        let mut names = Vec::new();
        let mut objects = Vec::new();
        for id in label_ids {
            let name = self.name_of(id).to_string();
            if !names.contains(&name) {
                names.push(name.clone());
            }
            objects.push(json!({ "id": id, "name": name }));
        }
        if names.is_empty() {
            names.push(primary.clone());
        }
        (primary, names, objects)
    }
}

/// `<compact UTC>Z-<id>`
fn message_name(rfc3339: &str, id: &str) -> String {
    let compact: String = rfc3339
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(15)
        .collect();
    format!("{compact}Z-{id}")
}

/// Convert Gmail's `internalDate` (epoch milliseconds as string or integer) to
/// `(RFC 3339 UTC string, nanoseconds since epoch)`.
fn parse_internal_date(v: &Value) -> (String, Option<i128>) {
    let ms = v
        .as_str()
        .and_then(|s| s.parse::<i64>().ok())
        .or_else(|| v.as_i64());
    match ms {
        Some(ms) if ms >= 0 => {
            let secs = (ms / 1000) as u64;
            let ns = i128::from(ms) * 1_000_000;
            (dfcore::host::rfc3339_utc(secs), Some(ns))
        }
        _ => (String::new(), None),
    }
}

/// Match include/exclude patterns against `<label>/<name>` across every label
/// on the message, and apply the `internalDate` time window.
fn decide_message(
    rules: &ScopeRules,
    label_names: &[String],
    primary_label: &str,
    msg_name: &str,
    account: &str,
    time_ns: Option<i128>,
) -> Decision {
    let s = rules.scope();
    if !s.accounts.is_empty() && !s.accounts.iter().any(|a| a.eq_ignore_ascii_case(account)) {
        return Decision::OutOfScope(format!("account {account} is not in scope"));
    }
    let mut paths: Vec<String> = label_names
        .iter()
        .map(|l| format!("{l}/{msg_name}"))
        .collect();
    let primary_path = format!("{primary_label}/{msg_name}");
    if !paths.contains(&primary_path) {
        paths.push(primary_path.clone());
    }
    if let Some(p) = s
        .exclude
        .iter()
        .find(|p| paths.iter().any(|lp| glob_match(p, lp)))
    {
        return Decision::OutOfScope(format!("excluded by {p}"));
    }
    let matched_path = if s.include.is_empty() {
        &primary_path
    } else if let Some(lp) = paths
        .iter()
        .find(|lp| s.include.iter().any(|p| glob_match(p, lp)))
    {
        lp
    } else {
        return Decision::OutOfScope("matches no include pattern".into());
    };
    rules.decide(&Candidate {
        path: matched_path,
        account: None,
        time_ns,
    })
}

/// Coarse Gmail `q=` search filter (`after:<epoch-86400> before:<epoch+86400>`)
/// widened by 1 day on each side so the exact `internalDate` check stays local
pub fn list_query(scope: &dfcore::manifest::Scope) -> Option<String> {
    const DAY: i128 = 86_400;
    const NS: i128 = 1_000_000_000;
    let mut parts = Vec::new();
    if let Some(nb) = &scope.not_before {
        let sec = dfcore::host::parse_rfc3339(nb).ok()?.div_euclid(NS) - DAY;
        parts.push(format!("after:{}", sec.max(0)));
    }
    if let Some(na) = &scope.not_after {
        let ns = dfcore::host::parse_rfc3339(na).ok()?;
        let sec = ns.div_euclid(NS) + i128::from(ns.rem_euclid(NS) != 0) + DAY;
        parts.push(format!("before:{}", sec.max(0)));
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

struct Session<'a> {
    args: &'a GmailArgs,
    api: Api,
    base: String,
    account: String,
    query: Option<String>,
    rules: ScopeRules,
    labels: LabelMap,
    collection: Collection,
    container: Container,
    ctx: &'a RunCtx<'a>,
    messages_listed: u64,
    bodies: u64,
}

impl Session<'_> {
    fn load_labels(&mut self) -> Result<()> {
        let url = format!("{}/labels", self.base);
        let v = self.api.get_json(&url)?;
        self.labels = LabelMap::from_json(&v);
        let summary: Vec<Value> = self
            .labels
            .by_id
            .values()
            .map(|l| json!({ "id": l.id, "name": l.name, "user": l.is_user }))
            .collect();
        self.collection.footprint(FootprintEntry::new(
            "request",
            json!({
                "request": "GET users/me/labels",
                "labels": summary,
            }),
        ))?;
        Ok(())
    }

    fn list_message_ids(&mut self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        let mut page_token: Option<String> = None;
        let q_param = self
            .query
            .as_deref()
            .map(|q| format!("&q={}", encode(q)))
            .unwrap_or_default();
        loop {
            common::check_stop(self.ctx.stop)?;
            let url = match &page_token {
                None => format!(
                    "{}/messages?includeSpamTrash=true&maxResults={PAGE}{q_param}",
                    self.base
                ),
                Some(tok) => format!(
                    "{}/messages?includeSpamTrash=true&maxResults={PAGE}{q_param}&pageToken={}",
                    self.base,
                    encode(tok)
                ),
            };
            let v = self.api.get_json(&url)?;
            if let Some(arr) = v["messages"].as_array() {
                for m in arr {
                    let id = m["id"]
                        .as_str()
                        .context("a message entry without id")?
                        .to_string();
                    ids.push(id);
                }
            }
            page_token = v["nextPageToken"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            if page_token.is_none() {
                break;
            }
        }
        self.messages_listed = ids.len() as u64;
        self.collection.footprint(FootprintEntry::new(
            "request",
            json!({
                "request": "GET users/me/messages?includeSpamTrash=true",
                "q": self.query,
                "messages": ids.len(),
            }),
        ))?;
        Ok(ids)
    }

    fn message(&mut self, id: &str) -> Result<()> {
        self.ctx.set_current(id);
        let min_url = format!("{}/messages/{}?format=minimal", self.base, encode(id));
        let min_resp = self.api.get(&min_url, "application/json")?;
        if min_resp.status != 200 {
            let mut item = Item::new(ItemStatus::Error, id);
            item.kind = Some("message".into());
            item.account = Some(self.account.clone());
            item.reason = Some(format!(
                "GET format=minimal: HTTP {}: {}",
                min_resp.status,
                min_resp.error_text()
            ));
            item.metadata = json!({ "id": id });
            common::record(&mut self.collection, item, self.ctx)?;
            return Ok(());
        }
        let m = match min_resp.json() {
            Ok(v) => v,
            Err(e) => {
                let mut item = Item::new(ItemStatus::Error, id);
                item.kind = Some("message".into());
                item.account = Some(self.account.clone());
                item.reason = Some(format!("GET format=minimal: {e:#}"));
                item.metadata = json!({ "id": id });
                common::record(&mut self.collection, item, self.ctx)?;
                return Ok(());
            }
        };
        let label_ids: Vec<String> = m["labelIds"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let (primary_label, label_names, label_objects) = self.labels.resolve(&label_ids);
        let (rfc3339, ns) = parse_internal_date(&m[TIME_BASIS]);
        let msg_name = message_name(&rfc3339, id);
        let path = format!("{primary_label}/{msg_name}");
        let times = Times {
            modified: (!rfc3339.is_empty()).then(|| rfc3339.clone()),
            ..Times::default()
        };
        let metadata = json!({
            "id": id,
            "threadId": m["threadId"],
            "labelIds": label_ids,
            "labels": label_objects,
            "labelNames": label_names,
            "internalDate": if rfc3339.is_empty() { Value::Null } else { json!(rfc3339) },
            "sizeEstimate": m["sizeEstimate"],
            "historyId": m["historyId"],
        });

        match decide_message(
            &self.rules,
            &label_names,
            &primary_label,
            &msg_name,
            &self.account,
            ns,
        ) {
            Decision::InScope => {}
            Decision::OutOfScope(reason) => {
                if self.args.scope.list_out_of_scope {
                    let mut item = Item::out_of_scope(path, reason);
                    item.kind = Some("message".into());
                    item.account = Some(self.account.clone());
                    item.times = times;
                    item.metadata = metadata;
                    common::record(&mut self.collection, item, self.ctx)?;
                } else {
                    self.collection.count_out_of_scope(&reason);
                    self.ctx.count(|p| &p.out_of_scope, 1);
                }
                return Ok(());
            }
        }

        let raw_url = format!("{}/messages/{}?format=raw", self.base, encode(id));
        let resp = self.api.get(&raw_url, "application/json")?;
        if resp.status != 200 {
            let mut item = Item::new(ItemStatus::Error, path);
            item.kind = Some("message".into());
            item.account = Some(self.account.clone());
            item.reason = Some(format!(
                "GET format=raw: HTTP {}: {}",
                resp.status,
                resp.error_text()
            ));
            item.times = times;
            item.metadata = metadata;
            common::record(&mut self.collection, item, self.ctx)?;
            return Ok(());
        }
        let raw_json = resp.json()?;
        let Some(raw_b64) = raw_json["raw"].as_str() else {
            let mut item = Item::new(ItemStatus::Error, path);
            item.kind = Some("message".into());
            item.account = Some(self.account.clone());
            item.reason = Some("GET format=raw response has no 'raw' field".into());
            item.times = times;
            item.metadata = metadata;
            common::record(&mut self.collection, item, self.ctx)?;
            return Ok(());
        };
        let Some(body) = b64decode(raw_b64) else {
            let mut item = Item::new(ItemStatus::Error, path);
            item.kind = Some("message".into());
            item.account = Some(self.account.clone());
            item.reason = Some("GET format=raw 'raw' field is not valid base64url".into());
            item.times = times;
            item.metadata = metadata;
            common::record(&mut self.collection, item, self.ctx)?;
            return Ok(());
        };

        let member = format!("{path}.eml");
        let stamp_ns = ns.unwrap_or(0);
        let stamps = Stamps {
            modified: stamp_ns,
            accessed: stamp_ns,
            changed: stamp_ns,
            birth: None,
        };
        let mut hasher = Hasher::new(self.args.md5, self.args.sha1);
        match self
            .container
            .add_file(&member, 0o644, &stamps, &mut &body[..], &mut hasher)
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
                common::record(&mut self.collection, item, self.ctx)?;
                return Ok(());
            }
        }
        self.bodies += 1;
        let mut item = Item::new(ItemStatus::Acquired, path);
        item.kind = Some("message".into());
        item.account = Some(self.account.clone());
        item.stored_as = Some(CONTAINER.into());
        item.member = Some(member);
        item.size = Some(body.len() as u64);
        item.hashes = hasher.finish();
        item.times = times;
        item.metadata = metadata;
        common::record(&mut self.collection, item, self.ctx)?;
        Ok(())
    }
}

fn header(args: &GmailArgs, scope: dfcore::manifest::Scope, ctx: &RunCtx) -> Result<Header> {
    let gmail = args.gmail_endpoint.trim_end_matches('/');
    let who = if args.mailbox.eq_ignore_ascii_case("me") {
        "me".to_string()
    } else {
        encode(&args.mailbox)
    };
    Ok(Header {
        action: AUDIT_ACTION.into(),
        case: common::case(&args.case),
        source: Source {
            kind: "gmail".into(),
            locator: format!("{gmail}/gmail/v1/users/{who}"),
            identity: Value::Null,
            details: Value::Null,
        },
        method: Method {
            tool: TOOL.into(),
            tool_version: VERSION.into(),
            system_revision: dfcore::release::system_revision(),
            argv: ctx.argv(),
            read_only_primitives: vec![
                format!("Gmail API: GET requests only with scope {GMAIL_SCOPE}; nothing is created, changed or deleted in the mailbox"),
                "GET /gmail/v1/users/me/messages/{id}?format=raw returns exact RFC 2822 bytes without changing UNREAD or any other label".into(),
            ],
            description: Some(format!(
                "Profile and labels read through the Gmail API; message IDs listed with includeSpamTrash=true \
                 (when the scope has a time window, narrowed on the server with q=after:<epoch>/before:<epoch> \
                 widened by one day on each side, and checked against exact {TIME_BASIS} locally); \
                 each message's minimal metadata (labelIds, {TIME_BASIS}, sizeEstimate, threadId, historyId) fetched \
                 first and decided against the scope before its body (?format=raw) is fetched; labels are not folders: \
                 each in-scope message is stored once under its first label in the order INBOX, SENT, DRAFT, SPAM, \
                 TRASH, then user labels by name, else All Mail, as <label>/<{TIME_BASIS} compact>Z-<id>.eml in \
                 {CONTAINER}, while include/exclude patterns are matched against <label>/<{TIME_BASIS} compact>Z-<id> \
                 across every label on the message (excluded if any label path matches an exclude pattern, otherwise \
                 included if there are no includes or if any label path matches one); the container is read back and \
                 every member hashed again"
            )),
        },
        scope,
        clocks: dfcore::manifest::Clocks {
            reference: common::reference_at(&args.clock, ctx.reference_entered_ns)?,
            ..Default::default()
        },
    })
}

fn flow(args: &GmailArgs, ctx: &RunCtx) -> Result<Flow> {
    Ok(match args.auth {
        GmailAuth::Token => {
            let path = args
                .token_file
                .as_ref()
                .ok_or_else(|| Usage("--auth token needs --token-file".into()))?;
            Flow::Token(first_line(path)?)
        }
        GmailAuth::ServiceAccount => {
            if args.mailbox.eq_ignore_ascii_case("me") || args.mailbox.trim().is_empty() {
                return Err(Usage(
                    "--auth service-account requires --mailbox <user@domain> (domain-wide delegation subject)"
                        .into(),
                )
                .into());
            }
            let path = args
                .key_file
                .as_ref()
                .ok_or_else(|| Usage("--auth service-account needs --key-file <sa.json>".into()))?;
            let raw = std::fs::read_to_string(path)
                .map_err(|e| Usage(format!("{}: {e}", path.display())))?;
            let sa: Value = serde_json::from_str(&raw)
                .map_err(|e| Usage(format!("{}: invalid JSON: {e}", path.display())))?;
            let client_email = sa["client_email"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Usage(format!("{}: missing client_email", path.display())))?
                .to_string();
            let pem = sa["private_key"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Usage(format!("{}: missing private_key", path.display())))?;
            let pkcs8_der = pem_der(pem).ok_or_else(|| {
                Usage(format!("{}: private_key is not valid PEM", path.display()))
            })?;
            RsaKeyPair::from_pkcs8(&pkcs8_der).map_err(|_| {
                Usage(format!(
                    "{}: private_key is not a valid PKCS#8 RSA key",
                    path.display()
                ))
            })?;
            Flow::ServiceAccount {
                client_email,
                private_key_id: sa["private_key_id"].as_str().map(str::to_string),
                project_id: sa["project_id"].as_str().map(str::to_string),
                pkcs8_der,
                mailbox: args.mailbox.clone(),
            }
        }
        GmailAuth::Installed => {
            let client_id = args.client_id.clone().ok_or_else(|| {
                Usage(
                    "--client-id is required for --auth installed (Desktop app OAuth client ID)"
                        .into(),
                )
            })?;
            let client_secret = match &args.client_secret_file {
                Some(p) => Zeroizing::new(first_line(p)?),
                None => need_secret(
                    ctx.console.as_ref(),
                    SecretAsk {
                        prompt: "Client secret: ".into(),
                        file_flag: "--client-secret-file",
                    },
                )?,
            };
            Flow::Installed {
                auth_url: args.auth_endpoint.clone(),
                client_id,
                client_secret,
            }
        }
    })
}

pub fn run_with(args: &GmailArgs, ctx: &RunCtx) -> Result<Outcome> {
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
                "a Gmail scope's time window applies to {TIME_BASIS}; set \"time_basis\": \"{TIME_BASIS}\""
            ))
            .into());
        }
    }
    let rules = scope.rules().map_err(|e| Usage(format!("{e:#}")))?;
    let query = list_query(&scope);
    for (name, url) in [
        ("--gmail-endpoint", &args.gmail_endpoint),
        ("--token-endpoint", &args.token_endpoint),
        ("--auth-endpoint", &args.auth_endpoint),
    ] {
        crate::http::parse_url(url).map_err(|e| Usage(format!("{name}: {e:#}")))?;
    }
    let (output, _) = common::check_output(&args.output, args.allow_tmpfs)?;
    let flow = flow(args, ctx)?;
    let gmail = args.gmail_endpoint.trim_end_matches('/').to_string();
    let accounts = scope.accounts.clone();

    let mut collection = Collection::create(&output, header(args, scope, ctx)?)?;
    for entry in ctx.footprint() {
        collection.footprint(entry)?;
    }
    let container = match Container::create(&output.join(CONTAINER), args.compress) {
        Ok(c) => c,
        Err(e) => {
            collection.finish(Completion::Aborted {
                reason: format!("{e:#}"),
            })?;
            return Err(e);
        }
    };
    let mut http = Client::new(Duration::from_secs(args.timeout)).for_run(ctx);
    ctx.set_stage("signing in");
    let (auth, record) =
        match Auth::sign_in_google(&mut http, flow, &args.token_endpoint, GMAIL_SCOPE, ctx) {
            Ok(a) => a,
            Err(e) => {
                let (reason, code) = common::not_started(&e, ctx.stop);
                collection.footprint(FootprintEntry::new("auth", json!({ "error": reason })))?;
                container.finish()?;
                let (code, finished, _) =
                    common::conclude(collection, &output, Some((reason, code)), ctx)?;
                return Ok(Outcome {
                    code,
                    summary: summary(&output, &finished, 0, 0),
                });
            }
        };
    collection.footprint(FootprintEntry::new("auth", record.clone()))?;

    let mut session = Session {
        args,
        base: format!("{gmail}/gmail/v1/users/me"),
        api: Api {
            http,
            auth,
            graph: gmail,
        },
        account: args.mailbox.clone(),
        query,
        rules,
        labels: LabelMap::default(),
        collection,
        container,
        ctx,
        messages_listed: 0,
        bodies: 0,
    };
    let result = (|| -> Result<()> {
        let profile_url = format!("{}/profile", session.base);
        let profile = session.api.get_json(&profile_url)?;
        if let Some(email) = profile["emailAddress"].as_str() {
            session.account = email.to_string();
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
        session.load_labels()?;
        let tls = tls_records(&output, &session.api.http)?;
        session.collection.set_source_identity(json!({
            "profile": profile,
            "auth": record,
            "tls": tls,
        }))?;
        ctx.set_phase(Phase::Listing);
        ctx.set_stage("listing the messages");
        let ids = session.list_message_ids()?;
        ctx.set_phase(Phase::Copying);
        ctx.set_total(ids.len() as u64);
        ctx.set_stage("fetching the messages (format=raw)");
        for id in &ids {
            common::check_stop(ctx.stop)?;
            ctx.count(|p| &p.entries, 1);
            session.message(id)?;
        }
        Ok(())
    })();
    let Session {
        mut collection,
        container,
        api: Api { http, auth, .. },
        messages_listed,
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
                "messages_listed": messages_listed,
                "bodies": bodies,
            }),
        )
    })?;
    let mut stopped = common::ended(result, ctx.stop);
    if let Err(e) = container.finish() {
        stopped.get_or_insert((format!("{e:#}"), 6));
    }
    let (code, finished, _) = common::conclude(collection, &output, stopped, ctx)?;
    ctx.set_phase(Phase::Done);
    Ok(Outcome {
        code,
        summary: summary(&output, &finished, messages_listed, bodies),
    })
}

fn summary(
    output: &Path,
    finished: &dfcore::manifest::Finished,
    messages_listed: u64,
    bodies: u64,
) -> Value {
    let m = &finished.manifest;
    json!({
        "collection": output,
        "status": m.status,
        "messages_listed": messages_listed,
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
    use dfcore::manifest::Scope;

    #[test]
    fn label_priority_and_multi_label_scope() {
        let labels = LabelMap::from_json(&json!({
            "labels": [
                { "id": "INBOX", "name": "INBOX", "type": "system" },
                { "id": "SENT", "name": "SENT", "type": "system" },
                { "id": "SPAM", "name": "SPAM", "type": "system" },
                { "id": "TRASH", "name": "TRASH", "type": "system" },
                { "id": "UNREAD", "name": "UNREAD", "type": "system" },
                { "id": "Label_1", "name": "Projekte/Ärger", "type": "user" },
                { "id": "Label_2", "name": "Archiv", "type": "user" }
            ]
        }));

        // INBOX + user label -> stored once under INBOX
        let (p, names, _) = labels.resolve(&["Label_1".into(), "INBOX".into(), "UNREAD".into()]);
        assert_eq!(p, "INBOX");
        assert!(names.contains(&"INBOX".to_string()));
        assert!(names.contains(&"Projekte/Ärger".to_string()));

        // Two user labels -> sorted by name ("Archiv" before "Projekte/Ärger")
        let (p, _, _) = labels.resolve(&["Label_1".into(), "Label_2".into()]);
        assert_eq!(p, "Archiv");

        // Only UNREAD or no labels -> All Mail
        let (p, _, _) = labels.resolve(&["UNREAD".into()]);
        assert_eq!(p, "All Mail");

        // Multi-label scope: excluded if ANY label matches exclude
        let rules = Scope {
            exclude: vec!["SPAM/**".into()],
            include: vec!["Projekte/Ärger/**".into()],
            ..Default::default()
        }
        .rules()
        .unwrap();

        // Has both INBOX and Projekte/Ärger -> included via Projekte/Ärger, even though primary is INBOX
        let dec = decide_message(
            &rules,
            &["INBOX".into(), "Projekte/Ärger".into()],
            "INBOX",
            "20260301T100000Z-m1",
            "alice@example.org",
            None,
        );
        assert_eq!(dec, Decision::InScope);

        // Has both Projekte/Ärger and SPAM -> excluded because SPAM/** matches
        let dec = decide_message(
            &rules,
            &["Projekte/Ärger".into(), "SPAM".into()],
            "SPAM",
            "20260301T100000Z-m2",
            "alice@example.org",
            None,
        );
        assert_eq!(dec, Decision::OutOfScope("excluded by SPAM/**".into()));

        assert_eq!(list_query(&Scope::default()), None);
        assert_eq!(
            list_query(&Scope {
                not_before: Some("2026-02-01T00:00:00Z".into()),
                not_after: Some("2026-06-01T00:00:00Z".into()),
                ..Default::default()
            })
            .as_deref(),
            Some("after:1769817600 before:1780358400")
        );
    }
}
