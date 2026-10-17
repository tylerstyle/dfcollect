//! `dfcollect imap`: mailboxes over IMAP, read-only by protocol.
//!
//! - Folders are opened with `EXAMINE`, never `SELECT`, and the server must
//!   confirm `[READ-ONLY]`.
//! - Message bodies are fetched with `BODY.PEEK[]`, which does not set `\Seen`.
//! - The scope is decided on each message's folder, account and INTERNALDATE
//!   before its body is fetched. Folders an exclude pattern removes
//!   (`Folder/**`) are not opened at all.
//! - Every message is stored byte for byte as `<folder>/<uid>.eml` in the
//!   container, with UIDVALIDITY, UID, flags, INTERNALDATE and size in its item.

pub(crate) mod client;
mod parse;
mod utf7;

use crate::{
    args::ImapArgs,
    common::{self, Phase, RunCtx},
    console::{need_secret, SecretAsk},
    container::{Container, CopyError, Hasher},
    files::CONTAINER,
    meta::Stamps,
    scope, Usage, TOOL, VERSION,
};
use anyhow::{bail, Context, Result};
pub use client::Security;
use client::{Connection, TlsInfo};
use dfcore::manifest::{
    glob_match, Candidate, Collection, Completion, Decision, FootprintEntry, Header, Item,
    ItemStatus, Method, ScopeRules, Source, Times,
};
use parse::{fetch_attr, Token};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
    time::Duration,
};
use zeroize::Zeroizing;

const AUDIT_ACTION: &str = "mail_acquisition";
/// Messages per body fetch, and the bytes one fetch may announce
const BATCH_MESSAGES: usize = 100;
const BATCH_BYTES: u64 = 64 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Auth {
    /// XOAUTH2 with a token file, else PLAIN where offered, else LOGIN
    Auto,
    Plain,
    Login,
    Xoauth2,
}

pub struct Outcome {
    pub code: u8,
    pub summary: Value,
}

enum Secret {
    Password(Zeroizing<String>),
    Token(Zeroizing<String>),
}

pub(crate) fn first_line(path: &Path) -> Result<String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| Usage(format!("{}: {e}", path.display())))?;
    let line = text.lines().next().unwrap_or_default().to_string();
    if line.is_empty() {
        return Err(Usage(format!("{} is empty", path.display())).into());
    }
    Ok(line)
}

fn secret(args: &ImapArgs, ctx: &RunCtx) -> Result<Secret> {
    if let Some(path) = &args.token_file {
        return Ok(Secret::Token(Zeroizing::new(first_line(path)?)));
    }
    if args.auth == Auth::Xoauth2 {
        return Err(Usage("--auth xoauth2 needs --token-file".into()).into());
    }
    match &args.password_file {
        Some(path) => Ok(Secret::Password(Zeroizing::new(first_line(path)?))),
        None => Ok(Secret::Password(need_secret(
            ctx.console.as_ref(),
            SecretAsk {
                prompt: format!("IMAP password for {}: ", args.user),
                file_flag: "--password-file",
            },
        )?)),
    }
}

fn host_port(server: &str, security: Security) -> Result<(String, u16)> {
    let default = if security == Security::Tls { 993 } else { 143 };
    // [v6]:port, host:port or host
    if let Some(rest) = server.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| Usage(format!("bad server {server}")))?;
        let port = match after.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| Usage(format!("bad port in {server}")))?,
            None => default,
        };
        return Ok((host.to_string(), port));
    }
    match server.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok((
            host.to_string(),
            port.parse()
                .map_err(|_| Usage(format!("bad port in {server}")))?,
        )),
        _ => Ok((server.to_string(), default)),
    }
}

/// A folder as LIST reports it.
struct Folder {
    /// The name as the server sent it, for commands
    raw: Vec<u8>,
    /// Decoded, with the server's hierarchy delimiter as `/`
    name: String,
    attributes: Vec<String>,
}

fn folder_name(raw: &[u8], delimiter: Option<char>) -> String {
    let decoded = utf7::decode(raw)
        .or_else(|| String::from_utf8(raw.to_vec()).ok())
        .unwrap_or_else(|| String::from_utf8_lossy(raw).into_owned());
    let name = match delimiter {
        Some('/') | None => decoded,
        Some(d) => decoded.replace('/', "%2F").replace(d, "/"),
    };
    if name.eq_ignore_ascii_case("INBOX") {
        "INBOX".into()
    } else {
        name
    }
}

/// Whether a folder needs opening at all: not removed by an exclude
/// pattern `X/**`, and some include pattern can match a message in it.
pub(crate) fn folder_scope(rules: &ScopeRules, name: &str) -> Option<String> {
    let scope = rules.scope();
    if let Some(p) = scope
        .exclude
        .iter()
        .find(|p| p.strip_suffix("/**").is_some_and(|q| glob_match(q, name)))
    {
        return Some(format!("folder excluded by {p}"));
    }
    // A folder is opened when an include pattern can match a message in it:
    // probed with UID 1 (`INBOX/**`, `INBOX/*`), or the pattern's folder part
    // names it (`INBOX/42`)
    if !scope.include.is_empty()
        && !scope.include.iter().any(|p| {
            glob_match(p, &format!("{name}/1"))
                || p.rsplit_once('/')
                    .is_some_and(|(folder, _)| glob_match(folder, name))
        })
    {
        return Some("folder matches no include pattern".into());
    }
    None
}

struct MessageMeta {
    uid: u64,
    flags: Vec<String>,
    internaldate: String,
    rfc3339: String,
    ns: i128,
    size: u64,
}

struct Session<'a> {
    args: &'a ImapArgs,
    rules: ScopeRules,
    conn: Connection,
    collection: Collection,
    container: Container,
    ctx: &'a RunCtx<'a>,
    folders_examined: u64,
}

/// A command for the footprint: what was sent (never a secret) and its result.
fn footprint_command(c: &mut Collection, command: &str, extra: Value) -> Result<()> {
    let mut detail = json!({ "command": command });
    if let (Some(d), Value::Object(e)) = (detail.as_object_mut(), extra) {
        d.extend(e);
    }
    c.footprint(FootprintEntry::new("command", detail))
}

fn capabilities(tokens: &[Token]) -> Vec<String> {
    tokens
        .iter()
        .skip_while(|t| {
            !t.atom()
                .is_some_and(|a| a.eq_ignore_ascii_case("CAPABILITY"))
        })
        .skip(1)
        .filter_map(|t| t.atom().map(str::to_string))
        .collect()
}

fn tls_record(dir: &Path, tls: &TlsInfo) -> Result<Value> {
    std::fs::create_dir_all(dir.join("tls"))?;
    let mut chain = Vec::new();
    for (i, der) in tls.chain.iter().enumerate() {
        let file = format!("tls/server-certificate-{i}.der");
        std::fs::write(dir.join(&file), der).with_context(|| format!("Cannot write {file}"))?;
        chain.push(json!({ "sha256": client::sha256_hex(der), "file": file }));
    }
    Ok(json!({
        "version": tls.version,
        "cipher": tls.cipher,
        "verified_by": tls.verified_by,
        "chain": chain,
    }))
}

impl Session<'_> {
    fn decide(&self, folder: &str, meta: &MessageMeta) -> Decision {
        self.rules.decide(&Candidate {
            path: &format!("{folder}/{}", meta.uid),
            account: Some(&self.args.user),
            time_ns: Some(meta.ns),
        })
    }

    fn folder_scope(&self, name: &str) -> Option<String> {
        folder_scope(&self.rules, name)
    }

    fn list(&mut self) -> Result<Vec<Folder>> {
        let mut folders = Vec::new();
        self.conn.command("LIST \"\" \"*\"", "LIST", |t, _| {
            if t.get(1)
                .and_then(Token::atom)
                .is_some_and(|a| a.eq_ignore_ascii_case("LIST"))
            {
                let attributes = match t.get(2) {
                    Some(Token::List(a)) => a
                        .iter()
                        .filter_map(|x| x.atom().map(str::to_string))
                        .collect(),
                    _ => Vec::new(),
                };
                let delimiter = match t.get(3) {
                    Some(Token::Bytes(d)) if d.len() == 1 => Some(d[0] as char),
                    _ => None,
                };
                let raw = match t.get(4) {
                    Some(Token::Bytes(b)) => b.clone(),
                    Some(Token::Atom(a)) => a.as_bytes().to_vec(),
                    _ => bail!("LIST response without a folder name"),
                };
                folders.push(Folder {
                    name: folder_name(&raw, delimiter),
                    raw,
                    attributes,
                });
            }
            Ok(())
        })?;
        footprint_command(
            &mut self.collection,
            "LIST \"\" \"*\"",
            json!({ "folders": folders.len() }),
        )?;
        folders.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(folders)
    }

    /// `EXAMINE`: the folder's UIDVALIDITY and message count; refuses a server
    /// that does not open it read-only.
    fn examine(&mut self, folder: &Folder) -> Result<(u64, u64)> {
        let Some(arg) = std::str::from_utf8(&folder.raw)
            .ok()
            .and_then(client::quote)
        else {
            bail!("folder name cannot be sent as a quoted string");
        };
        let (mut exists, mut uidvalidity) = (0u64, 0u64);
        let tagged = self.conn.command(
            &format!("EXAMINE {arg}"),
            &format!("EXAMINE {}", folder.name),
            |t, _| {
                if t.get(2)
                    .and_then(Token::atom)
                    .is_some_and(|a| a.eq_ignore_ascii_case("EXISTS"))
                {
                    exists = t.get(1).and_then(Token::number).unwrap_or(0);
                }
                if let Some(Token::Bracket(code)) = t.get(2) {
                    if code
                        .first()
                        .and_then(Token::atom)
                        .is_some_and(|a| a.eq_ignore_ascii_case("UIDVALIDITY"))
                    {
                        uidvalidity = code.get(1).and_then(Token::number).unwrap_or(0);
                    }
                }
                Ok(())
            },
        )?;
        let read_only = matches!(
            tagged.get(2),
            Some(Token::Bracket(code)) if code.first().and_then(Token::atom).is_some_and(|a| a.eq_ignore_ascii_case("READ-ONLY"))
        );
        footprint_command(
            &mut self.collection,
            &format!("EXAMINE {arg}"),
            json!({ "folder": folder.name, "uidvalidity": uidvalidity, "exists": exists, "read_only": read_only }),
        )?;
        if !read_only {
            bail!(
                "the server did not confirm EXAMINE {} as [READ-ONLY]; stopping before anything else is sent",
                folder.name
            );
        }
        Ok((uidvalidity, exists))
    }

    fn message_metadata(&mut self) -> Result<Vec<MessageMeta>> {
        let mut out = Vec::new();
        let command = "UID FETCH 1:* (UID FLAGS INTERNALDATE RFC822.SIZE)";
        self.conn.command(command, command, |t, _| {
            if !t
                .get(2)
                .and_then(Token::atom)
                .is_some_and(|a| a.eq_ignore_ascii_case("FETCH"))
            {
                return Ok(());
            }
            let Some(Token::List(attrs)) = t.get(3) else {
                return Ok(());
            };
            let uid = fetch_attr(attrs, "UID")
                .and_then(Token::number)
                .context("FETCH without UID")?;
            let flags = match fetch_attr(attrs, "FLAGS") {
                Some(Token::List(f)) => f
                    .iter()
                    .filter_map(|x| x.atom().map(str::to_string))
                    .collect(),
                _ => Vec::new(),
            };
            let internaldate = fetch_attr(attrs, "INTERNALDATE")
                .and_then(Token::text)
                .context("FETCH without INTERNALDATE")?;
            let (rfc3339, ns) = parse::internaldate(&internaldate)?;
            let size = fetch_attr(attrs, "RFC822.SIZE")
                .and_then(Token::number)
                .unwrap_or(0);
            out.push(MessageMeta {
                uid,
                flags,
                internaldate,
                rfc3339,
                ns,
                size,
            });
            Ok(())
        })?;
        footprint_command(
            &mut self.collection,
            command,
            json!({ "messages": out.len() }),
        )?;
        out.sort_by_key(|m| m.uid);
        Ok(out)
    }

    /// Fetch bodies of `batch` and store them. Returns `Err` only when the
    /// container cannot be written or the session broke.
    fn fetch_bodies(
        &mut self,
        folder: &Folder,
        uidvalidity: u64,
        batch: &[&MessageMeta],
    ) -> Result<()> {
        let set: Vec<String> = batch.iter().map(|m| m.uid.to_string()).collect();
        let command = format!("UID FETCH {} (UID BODY.PEEK[])", set.join(","));
        let by_uid: HashMap<u64, &&MessageMeta> = batch.iter().map(|m| (m.uid, m)).collect();
        let mut stored = BTreeSet::new();
        let mut bytes = 0u64;
        let (args, container, collection, ctx) = (
            &self.args,
            &mut self.container,
            &mut self.collection,
            self.ctx,
        );
        self.conn.command(
            &command,
            &format!("UID FETCH <{} UIDs> (UID BODY.PEEK[])", set.len()),
            |t, _| {
                if !t
                    .get(2)
                    .and_then(Token::atom)
                    .is_some_and(|a| a.eq_ignore_ascii_case("FETCH"))
                {
                    return Ok(());
                }
                let Some(Token::List(attrs)) = t.get(3) else {
                    return Ok(());
                };
                let Some(uid) = fetch_attr(attrs, "UID").and_then(Token::number) else {
                    return Ok(());
                };
                let Some(Token::Bytes(body)) = fetch_attr(attrs, "BODY[]") else {
                    return Ok(());
                };
                let Some(meta) = by_uid.get(&uid) else {
                    return Ok(());
                };
                if !stored.insert(uid) {
                    return Ok(());
                }
                let member = format!("{}/{uid}.eml", folder.name);
                let stamps = Stamps {
                    modified: meta.ns,
                    accessed: meta.ns,
                    changed: meta.ns,
                    birth: None,
                };
                let mut hasher = Hasher::new(args.md5, args.sha1);
                match container.add_file(&member, 0o644, &stamps, &mut &body[..], &mut hasher) {
                    Ok(_) => {}
                    Err(CopyError::Container(e)) => return Err(e),
                    Err(CopyError::Source(e)) => return Err(e.into()),
                    // Two folder names that normalize alike: keep going
                    Err(CopyError::Duplicate(name)) => {
                        let mut item =
                            Item::new(ItemStatus::Error, format!("{}/{uid}", folder.name));
                        item.kind = Some("message".into());
                        item.account = Some(args.user.clone());
                        item.reason =
                            Some(format!("another message already has the container name {name}"));
                        item.metadata =
                            json!({ "folder": folder.name, "uidvalidity": uidvalidity, "uid": uid });
                        collection.add(item)?;
                        ctx.count(|p| &p.errors, 1);
                        return Ok(());
                    }
                }
                bytes += body.len() as u64;
                ctx.count(|p| &p.files, 1);
                ctx.count(|p| &p.bytes, body.len() as u64);
                let mut item = Item::new(ItemStatus::Acquired, format!("{}/{uid}", folder.name));
                item.kind = Some("message".into());
                item.account = Some(args.user.clone());
                item.stored_as = Some(CONTAINER.into());
                item.member = Some(member);
                item.size = Some(body.len() as u64);
                item.hashes = hasher.finish();
                item.times = Times {
                    modified: Some(meta.rfc3339.clone()),
                    ..Times::default()
                };
                let mut md = json!({
                    "folder": folder.name,
                    "uidvalidity": uidvalidity,
                    "uid": uid,
                    "flags": meta.flags,
                    "internaldate": meta.internaldate,
                    "rfc822_size": meta.size,
                });
                if folder.raw != folder.name.as_bytes() {
                    md["folder_raw"] = json!(String::from_utf8_lossy(&folder.raw));
                }
                if meta.size != body.len() as u64 {
                    md["size_differs_from_rfc822_size"] = json!(true);
                }
                item.metadata = md;
                collection.add(item)?;
                Ok(())
            },
        )?;
        footprint_command(
            &mut self.collection,
            &format!("UID FETCH <{} UIDs> (UID BODY.PEEK[])", set.len()),
            json!({ "folder": folder.name, "uids_requested": set.len(), "bodies": stored.len(), "bytes": bytes }),
        )?;
        for m in batch.iter().filter(|m| !stored.contains(&m.uid)) {
            let mut item = Item::new(ItemStatus::Error, format!("{}/{}", folder.name, m.uid));
            item.kind = Some("message".into());
            item.account = Some(self.args.user.clone());
            item.reason =
                Some("the server returned no body (expunged during the acquisition?)".into());
            item.metadata =
                json!({ "folder": folder.name, "uidvalidity": uidvalidity, "uid": m.uid });
            self.collection.add(item)?;
        }
        Ok(())
    }

    fn folder(&mut self, folder: &Folder) -> Result<()> {
        if let Some(reason) = self.folder_scope(&folder.name) {
            self.collection.count_out_of_scope(&reason);
            self.ctx.count(|p| &p.out_of_scope, 1);
            return Ok(());
        }
        self.ctx.set_current(&folder.name);
        if std::str::from_utf8(&folder.raw)
            .ok()
            .and_then(client::quote)
            .is_none()
        {
            // Not modified UTF-7 as IMAP4rev1 requires: record it, go on
            let mut item = Item::new(ItemStatus::Error, folder.name.clone());
            item.kind = Some("folder".into());
            item.account = Some(self.args.user.clone());
            item.reason = Some(
                "the server lists this folder under a name that cannot be sent back as a quoted string; not opened"
                    .into(),
            );
            self.collection.add(item)?;
            return Ok(());
        }
        let (uidvalidity, exists) = self.examine(folder)?;
        self.folders_examined += 1;
        if exists == 0 {
            return Ok(());
        }
        let messages = self.message_metadata()?;
        let mut wanted = Vec::new();
        for m in &messages {
            match self.decide(&folder.name, m) {
                Decision::InScope => wanted.push(m),
                Decision::OutOfScope(reason) => {
                    if self.args.scope.list_out_of_scope {
                        let mut item =
                            Item::out_of_scope(format!("{}/{}", folder.name, m.uid), reason);
                        item.kind = Some("message".into());
                        item.account = Some(self.args.user.clone());
                        item.times = Times {
                            modified: Some(m.rfc3339.clone()),
                            ..Times::default()
                        };
                        item.metadata = json!({ "folder": folder.name, "uidvalidity": uidvalidity, "uid": m.uid });
                        self.collection.add(item)?;
                    } else {
                        self.collection.count_out_of_scope(&reason);
                    }
                    self.ctx.count(|p| &p.out_of_scope, 1);
                }
            }
        }
        let mut batch = Vec::new();
        let mut batch_bytes = 0u64;
        self.ctx.count(|p| &p.entries, wanted.len() as u64);
        for m in wanted {
            common::check_stop(self.ctx.stop)?;
            if !batch.is_empty()
                && (batch.len() >= BATCH_MESSAGES || batch_bytes + m.size > BATCH_BYTES)
            {
                self.fetch_bodies(folder, uidvalidity, &batch)?;
                batch.clear();
                batch_bytes = 0;
            }
            batch_bytes += m.size;
            batch.push(m);
        }
        if !batch.is_empty() {
            self.fetch_bodies(folder, uidvalidity, &batch)?;
        }
        Ok(())
    }
}

fn header(
    args: &ImapArgs,
    host: &str,
    port: u16,
    scope: dfcore::manifest::Scope,
    ctx: &RunCtx,
) -> Result<Header> {
    let scheme = match args.security {
        Security::Tls => "imaps",
        Security::StartTls => "imap+starttls",
        Security::Plaintext => "imap",
    };
    Ok(Header {
        action: AUDIT_ACTION.into(),
        case: common::case(&args.case),
        source: Source {
            kind: "imap".into(),
            locator: format!("{scheme}://{}@{host}:{port}", args.user),
            identity: Value::Null,
            details: Value::Null,
        },
        method: Method {
            tool: TOOL.into(),
            tool_version: VERSION.into(),
            system_revision: dfcore::release::system_revision(),
            argv: ctx.argv(),
            read_only_primitives: vec![
                "IMAP EXAMINE (read-only), [READ-ONLY] required".into(),
                "UID FETCH BODY.PEEK[] (does not set \\Seen)".into(),
            ],
            description: Some(format!(
                "Folders listed with LIST, opened with EXAMINE; message metadata fetched first and every \
                 message decided by the scope before its body is fetched; bodies stored byte for byte as \
                 <folder>/<uid>.eml in {CONTAINER}; the container is read back and every member hashed again"
            )),
        },
        scope,
        clocks: dfcore::manifest::Clocks {
            reference: common::reference_at(&args.clock, ctx.reference_entered_ns)?,
            ..Default::default()
        },
    })
}

pub fn run_with(args: &ImapArgs, ctx: &RunCtx) -> Result<Outcome> {
    let mut scope = scope::build(&args.scope)?;
    if scope.not_before.is_some() || scope.not_after.is_some() {
        if args.scope.scope.is_none() {
            scope.time_basis = Some("INTERNALDATE".into());
        } else if !scope
            .time_basis
            .as_deref()
            .is_some_and(|b| b.eq_ignore_ascii_case("INTERNALDATE"))
        {
            return Err(Usage("an IMAP scope's time window applies to INTERNALDATE; set \"time_basis\": \"INTERNALDATE\"".into()).into());
        }
    }
    if !scope.accounts.is_empty() && !scope.accounts.contains(&args.user) {
        return Err(Usage(format!(
            "--user {} is not among the scope's accounts",
            args.user
        ))
        .into());
    }
    let rules = scope.rules().map_err(|e| Usage(format!("{e:#}")))?;
    let (host, port) = host_port(&args.server, args.security)?;
    let (output, _) = common::check_output(&args.output, args.allow_tmpfs)?;
    let secret = secret(args, ctx)?;

    let mut collection = Collection::create(&output, header(args, &host, port, scope, ctx)?)?;
    for entry in ctx.footprint() {
        collection.footprint(entry)?;
    }
    ctx.set_phase(Phase::Listing);
    ctx.set_stage(&format!("connecting to {host}:{port}"));
    let container = match Container::create(&output.join(CONTAINER), args.compress) {
        Ok(c) => c,
        Err(e) => {
            collection.finish(Completion::Aborted {
                reason: format!("{e:#}"),
            })?;
            return Err(e);
        }
    };
    let timeout = Duration::from_secs(args.timeout);
    let connected = match args.security {
        Security::StartTls => {
            client::connect_starttls(&host, port, args.tls_sha256.as_deref(), timeout)
                .map(|(c, tls, g)| (c, Some(tls), g))
        }
        Security::Tls => {
            Connection::connect(&host, port, true, args.tls_sha256.as_deref(), timeout)
        }
        Security::Plaintext => Connection::connect(&host, port, false, None, timeout),
    };
    let (conn, tls, greeting) = match connected {
        Ok(c) => c,
        Err(e) => {
            let (reason, code) = common::not_started(&e, ctx.stop);
            collection.footprint(FootprintEntry::new(
                "connect",
                json!({ "server": format!("{host}:{port}"), "error": reason }),
            ))?;
            container.finish()?;
            let (code, finished, _) =
                common::conclude(collection, &output, Some((reason, code)), ctx)?;
            return Ok(Outcome {
                code,
                summary: summary(&output, &finished, 0),
            });
        }
    };
    collection.footprint(FootprintEntry::new(
        "connect",
        json!({ "server": format!("{host}:{port}"), "peer": conn.peer.to_string(), "security": format!("{:?}", args.security) }),
    ))?;
    let tls_json = match &tls {
        Some(t) => {
            let j = tls_record(&output, t)?;
            collection.footprint(FootprintEntry::new("tls", j.clone()))?;
            j
        }
        None => Value::Null,
    };
    let greeting_text: Vec<String> = greeting.iter().skip(2).filter_map(Token::text).collect();

    let mut session = Session {
        args,
        rules,
        conn,
        collection,
        container,
        ctx,
        folders_examined: 0,
    };
    let result = (|| -> Result<()> {
        let mut caps = Vec::new();
        session.conn.command("CAPABILITY", "CAPABILITY", |t, _| {
            caps.extend(capabilities(&t));
            Ok(())
        })?;
        footprint_command(
            &mut session.collection,
            "CAPABILITY",
            json!({ "capabilities": caps }),
        )?;
        let has = |c: &str| caps.iter().any(|x| x.eq_ignore_ascii_case(c));
        let method = match (args.auth, &secret) {
            (Auth::Xoauth2, _) | (Auth::Auto, Secret::Token(_)) => "XOAUTH2",
            (Auth::Plain, _) => "PLAIN",
            (Auth::Login, _) => "LOGIN",
            (Auth::Auto, Secret::Password(_)) if has("AUTH=PLAIN") => "PLAIN",
            (Auth::Auto, Secret::Password(_)) => "LOGIN",
        };
        if method == "LOGIN" && has("LOGINDISABLED") {
            bail!("the server disables LOGIN on this connection; use TLS or --auth plain");
        }
        match (method, &secret) {
            ("XOAUTH2", Secret::Token(token)) => {
                let resp = Zeroizing::new(format!(
                    "user={}\x01auth=Bearer {}\x01\x01",
                    args.user,
                    token.as_str()
                ));
                session.conn.authenticate("XOAUTH2", resp.as_bytes())?;
            }
            ("PLAIN", Secret::Password(pw)) => {
                let resp = Zeroizing::new(format!("\0{}\0{}", args.user, pw.as_str()));
                session.conn.authenticate("PLAIN", resp.as_bytes())?;
            }
            ("LOGIN", Secret::Password(pw)) => {
                session.conn.login(&args.user, pw)?;
            }
            _ => bail!("--auth {method} does not fit the given secret"),
        }
        session.collection.footprint(FootprintEntry::new(
            "auth",
            json!({ "method": method, "user": args.user }),
        ))?;
        let mut caps_after = Vec::new();
        session.conn.command("CAPABILITY", "CAPABILITY", |t, _| {
            caps_after.extend(capabilities(&t));
            Ok(())
        })?;
        session.collection.set_source_identity(json!({
            "peer": session.conn.peer.to_string(),
            "greeting": greeting_text.join(" "),
            "capabilities": caps_after,
            "tls": tls_json,
        }))?;
        let folders = session.list()?;
        ctx.set_phase(Phase::Copying);
        let n = folders.len();
        for (i, folder) in folders.iter().enumerate() {
            common::check_stop(ctx.stop)?;
            ctx.set_stage(&format!("folder {} ({}/{n})", folder.name, i + 1));
            if folder.attributes.iter().any(|a| {
                a.eq_ignore_ascii_case("\\Noselect") || a.eq_ignore_ascii_case("\\NonExistent")
            }) {
                continue;
            }
            session.folder(folder)?;
        }
        Ok(())
    })();
    let _ = session.conn.command("LOGOUT", "LOGOUT", |_, _| Ok(()));
    let Session {
        mut collection,
        container,
        conn,
        folders_examined,
        ..
    } = session;
    collection.footprint(FootprintEntry {
        bytes_sent: Some(conn.sent),
        bytes_received: Some(conn.received),
        ..FootprintEntry::new(
            "disconnect",
            json!({ "folders_examined": folders_examined }),
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
        summary: summary(&output, &finished, folders_examined),
    })
}

fn summary(output: &Path, finished: &dfcore::manifest::Finished, folders: u64) -> Value {
    let m = &finished.manifest;
    json!({
        "collection": output,
        "status": m.status,
        "folders_examined": folders,
        "messages": m.totals.acquired,
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
    fn folder_names_are_decoded_and_normalized() {
        assert_eq!(folder_name(b"inbox", Some('/')), "INBOX");
        assert_eq!(
            folder_name(b"INBOX.Entw&APw-rfe", Some('.')),
            "INBOX/Entw\u{fc}rfe"
        );
        assert_eq!(folder_name(b"a/b.c", Some('.')), "a%2Fb/c");
        assert_eq!(folder_name(b"Archiv/2026", Some('/')), "Archiv/2026");
    }

    #[test]
    fn include_patterns_select_folders() {
        let rules = |include: &[&str]| {
            dfcore::manifest::Scope {
                include: include.iter().map(|s| s.to_string()).collect(),
                exclude: vec!["INBOX/Spam/**".into()],
                ..Default::default()
            }
            .rules()
            .unwrap()
        };
        let opened = |r: &ScopeRules, folder: &str| folder_scope(r, folder).is_none();
        let r = rules(&["INBOX/**"]);
        assert!(opened(&r, "INBOX") && opened(&r, "INBOX/Sub"));
        assert!(!opened(&r, "Sent") && !opened(&r, "INBOX/Spam"));
        let r = rules(&["INBOX/42", "Archiv/*/1"]);
        assert!(opened(&r, "INBOX") && opened(&r, "Archiv/2026"));
        assert!(!opened(&r, "INBOX/Sub") && !opened(&r, "Archiv"));
        assert!(opened(&rules(&[]), "Anything"));
    }

    #[test]
    fn servers_and_ports() {
        assert_eq!(
            host_port("mail.example.org", Security::Tls).unwrap(),
            ("mail.example.org".into(), 993)
        );
        assert_eq!(
            host_port("mail.example.org:1143", Security::Tls).unwrap(),
            ("mail.example.org".into(), 1143)
        );
        assert_eq!(
            host_port("[2001:db8::1]", Security::StartTls).unwrap(),
            ("2001:db8::1".into(), 143)
        );
        assert_eq!(
            host_port("[2001:db8::1]:10993", Security::Tls).unwrap(),
            ("2001:db8::1".into(), 10993)
        );
        assert!(host_port("host:notaport", Security::Tls).is_err());
    }
}
