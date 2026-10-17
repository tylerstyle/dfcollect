//! `dfcollect cloud`: files from a cloud or remote service (OneDrive,
//! SharePoint, Google Drive, Dropbox, S3, WebDAV/Nextcloud, SFTP, Box, …)
//! through rclone, which never writes to the remote here.
//!
//! - Only `rclone lsjson` and `rclone cat` touch the remote, and both only
//!   read. `rclone version` and `rclone config show` are recorded, the latter
//!   with secrets removed.
//! - The remote is listed with the provider's hashes, IDs and metadata before
//!   and after. Both listings go into the container, and files that changed in
//!   between are recorded.
//! - The scope (path, modification time) is decided on the listing, before
//!   anything is downloaded.
//! - Every file is streamed from `rclone cat` into the container. On the way
//!   it is hashed (SHA-256, MD5/SHA-1 on request) and checked against every
//!   provider hash dfcollect can compute: MD5, SHA-1, QuickXorHash, Dropbox.
//! - Google-native documents are exported by rclone (in the formats its
//!   options name). Their size isn't known beforehand and they carry no hash.

use crate::{
    args::CloudArgs,
    common::{self, Counting, Phase, PreviewNote, RunCtx, Stopped},
    container::{Container, CopyError, Hasher},
    files::CONTAINER,
    meta::Stamps,
    provider_hash::Provider,
    scope, Usage, TOOL, VERSION,
};
use anyhow::{bail, Context, Result};
use dfcore::manifest::{
    Candidate, Collection, Completion, Decision, FootprintEntry, Header, Item, ItemStatus, Method,
    ScopeRules, Source, Times,
};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeMap,
    io::Read,
    process::{Command, Stdio},
};

const AUDIT_ACTION: &str = "cloud_acquisition";

pub struct Outcome {
    pub code: u8,
    pub summary: Value,
}

/// `remote:` and `remote:dir` (a local path is for `dfcollect files`)
pub fn split_source(source: &str) -> Result<(String, String)> {
    match source.split_once(':') {
        Some((remote, path))
            if !remote.is_empty()
                && remote
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_-. ".contains(c)) =>
        {
            // A leading '/' stays: `local:/x` and `sftp:/x` are absolute,
            // `sftp:x` is below the login's home; `REMOTE:/` is the root
            let trimmed = path.trim_end_matches('/');
            let path = if trimmed.is_empty() && path.starts_with('/') {
                "/"
            } else {
                trimmed
            };
            Ok((remote.to_string(), path.to_string()))
        }
        _ => Err(Usage(format!(
            "{source}: give an rclone remote, REMOTE: or REMOTE:path (a local directory is for dfcollect files)"
        ))
        .into()),
    }
}

/// The remote path of a listed file
pub fn remote_path(remote: &str, base: &str, rel: &str) -> String {
    match base {
        "" => format!("{remote}:{rel}"),
        "/" => format!("{remote}:/{rel}"),
        _ => format!("{remote}:{base}/{rel}"),
    }
}

/// What rclone lists: `REMOTE:`, `REMOTE:/` or `REMOTE:path`
pub fn listing_target(remote: &str, base: &str) -> String {
    format!("{remote}:{base}")
}

/// Words that mark a configuration key or an option as holding a secret
/// (Azure SAS URLs carry their signature; headers and cookies can carry auth)
const SECRET_WORDS: [&str; 8] = [
    "token",
    "secret",
    "pass",
    "key",
    "credential",
    "sas_url",
    "cookie",
    "header",
];

/// Config lines with secret values removed (tokens, secrets, passwords, keys)
pub fn redact_config(text: &str) -> String {
    text.lines()
        .map(|l| match l.split_once('=') {
            Some((k, _))
                if SECRET_WORDS
                    .iter()
                    .any(|w| k.trim().to_ascii_lowercase().contains(w)) =>
            {
                format!("{}= <removed>", k)
            }
            _ => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Extra rclone arguments for the record, with secret-looking values removed
pub fn redact_args(args: &[String]) -> Vec<String> {
    let secret = |a: &str| {
        let l = a.to_ascii_lowercase();
        SECRET_WORDS.iter().any(|w| l.contains(w))
    };
    let mut out = Vec::new();
    let mut hide_next = false;
    for a in args {
        if hide_next {
            out.push("<removed>".into());
            hide_next = false;
        } else if a.starts_with("--") && secret(a) {
            match a.split_once('=') {
                Some((k, _)) => out.push(format!("{k}=<removed>")),
                None => {
                    out.push(a.clone());
                    hide_next = true;
                }
            }
        } else {
            out.push(a.clone());
        }
    }
    out
}

/// What changed on the remote between two listings: added, removed, changed
pub fn listing_changes(before: &[Value], after: &[Value]) -> Value {
    let key = |e: &Value| {
        e["ID"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| e["Path"].as_str().unwrap_or("").to_string())
    };
    let summary = |e: &Value| json!({ "Path": e["Path"], "Size": e["Size"], "ModTime": e["ModTime"], "Hashes": e["Hashes"] });
    let b: BTreeMap<String, &Value> = before.iter().map(|e| (key(e), e)).collect();
    let a: BTreeMap<String, &Value> = after.iter().map(|e| (key(e), e)).collect();
    let added: Vec<Value> = a
        .iter()
        .filter(|(k, _)| !b.contains_key(*k))
        .map(|(_, e)| summary(e))
        .collect();
    let removed: Vec<Value> = b
        .iter()
        .filter(|(k, _)| !a.contains_key(*k))
        .map(|(_, e)| summary(e))
        .collect();
    let changed: Vec<Value> = b
        .iter()
        .filter_map(|(k, eb)| {
            let ea = a.get(k)?;
            (summary(eb) != summary(ea))
                .then(|| json!({ "before": summary(eb), "after": summary(ea) }))
        })
        .collect();
    json!({ "added": added, "removed": removed, "changed": changed })
}

/// Reads from rclone and feeds the provider hashes on the way
struct Tee<R> {
    inner: R,
    providers: Vec<(String, Provider)>,
}

impl<R: Read> Read for Tee<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        for (_, p) in &mut self.providers {
            p.update(&buf[..n]);
        }
        Ok(n)
    }
}

/// rclone with the configuration file and the extra options of the command line
fn rclone(args: &CloudArgs) -> Command {
    let mut c = Command::new("rclone");
    if let Some(cfg) = &args.rclone_config {
        c.arg("--config").arg(cfg);
    }
    c.args(&args.rclone_args);
    c
}

/// The scope and its rules; a cloud time window applies to the modification time
fn scope_rules(args: &CloudArgs) -> Result<(dfcore::manifest::Scope, ScopeRules)> {
    let mut scope = scope::build(&args.scope)?;
    if scope.not_before.is_some() || scope.not_after.is_some() {
        if args.scope.scope.is_none() {
            scope.time_basis = Some("modified".into());
        } else if !scope
            .time_basis
            .as_deref()
            .is_some_and(|b| b.eq_ignore_ascii_case("modified"))
        {
            return Err(Usage(
                "a cloud scope's time window applies to the modification time; set \"time_basis\": \"modified\"".into(),
            )
            .into());
        }
    }
    let rules = scope.rules().map_err(|e| Usage(format!("{e:#}")))?;
    Ok((scope, rules))
}

struct Session<'a> {
    args: &'a CloudArgs,
    ctx: &'a RunCtx<'a>,
    remote: String,
    base: String,
    rules: ScopeRules,
    collection: Collection,
    container: Container,
    acquired: u64,
    mismatched: u64,
}

impl Session<'_> {
    fn rclone(&self) -> Command {
        rclone(self.args)
    }

    fn run_rclone(&mut self, args: &[&str]) -> Result<Vec<u8>> {
        let mut cmd = self.rclone();
        cmd.args(args);
        let out = common::output_unless_stopped(cmd, self.ctx.stop).map_err(|e| {
            if e.downcast_ref::<Stopped>().is_some() {
                e
            } else {
                e.context("Cannot run rclone")
            }
        })?;
        self.collection.footprint(FootprintEntry::new(
            "command",
            json!({
                "command": format!("rclone {} {}", redact_args(&self.args.rclone_args).join(" "), args.join(" ")),
                "exit": out.status.code(),
                "stdout_bytes": out.stdout.len(),
            }),
        ))?;
        if !out.status.success() {
            bail!(
                "rclone {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(out.stdout)
    }

    fn listing(&mut self, member: &str) -> Result<Vec<Value>> {
        let target = listing_target(&self.remote, &self.base);
        let raw = self.run_rclone(&[
            "lsjson",
            "-R",
            "--hash",
            "--metadata",
            "--files-only",
            &target,
        ])?;
        let entries: Vec<Value> =
            serde_json::from_slice(&raw).context("rclone lsjson output is not JSON")?;
        let now = dfcore::host::unix_now_ns();
        let stamps = Stamps {
            modified: now,
            accessed: now,
            changed: now,
            birth: None,
        };
        let mut hasher = Hasher::new(self.args.md5, self.args.sha1);
        match self
            .container
            .add_file(member, 0o644, &stamps, &mut &raw[..], &mut hasher)
        {
            Ok(_) => {}
            Err(CopyError::Container(e)) => return Err(e),
            Err(CopyError::Source(e)) => return Err(e.into()),
            Err(CopyError::Duplicate(n)) => bail!("{n} is in the container already"),
        }
        let mut item = Item::new(ItemStatus::Acquired, member);
        item.kind = Some("listing".into());
        item.stored_as = Some(CONTAINER.into());
        item.member = Some(member.into());
        item.size = Some(raw.len() as u64);
        item.hashes = hasher.finish();
        item.metadata = json!({ "remote": target, "entries": entries.len(), "command": "rclone lsjson -R --hash --metadata --files-only" });
        self.collection.add(item)?;
        Ok(entries)
    }

    fn file(&mut self, entry: &Value) -> Result<()> {
        let rel = entry["Path"]
            .as_str()
            .context("a listing entry without Path")?
            .to_string();
        let mod_time = entry["ModTime"].as_str().map(str::to_string);
        let ns = mod_time
            .as_deref()
            .and_then(|t| dfcore::host::parse_rfc3339(t).ok());
        let times = Times {
            modified: mod_time.clone(),
            ..Times::default()
        };
        match self.rules.decide(&Candidate {
            path: &rel,
            account: None,
            time_ns: ns,
        }) {
            Decision::InScope => {}
            Decision::OutOfScope(reason) => {
                self.ctx.count(|p| &p.out_of_scope, 1);
                if self.args.scope.list_out_of_scope {
                    let mut item = Item::out_of_scope(rel, reason);
                    item.kind = Some("file".into());
                    item.times = times;
                    item.metadata = entry.clone();
                    self.collection.add(item)?;
                } else {
                    self.collection.count_out_of_scope(&reason);
                }
                return Ok(());
            }
        }
        let listed: Map<String, Value> = entry["Hashes"].as_object().cloned().unwrap_or_default();
        let mut providers = Vec::new();
        let mut not_checked = Vec::new();
        for (name, v) in &listed {
            if v.as_str().is_some_and(|s| !s.is_empty()) {
                match Provider::for_name(name) {
                    Some(p) => providers.push((name.clone(), p)),
                    None => not_checked.push(name.clone()),
                }
            }
        }
        let src = remote_path(&self.remote, &self.base, &rel);
        self.ctx.set_current(&rel);
        let mut child = self
            .rclone()
            .arg("cat")
            .arg(&src)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Cannot run rclone")?;
        let stdout = child.stdout.take().context("rclone stdout")?;
        let mut stderr = child.stderr.take().context("rclone stderr")?;
        let err_thread = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            s
        });
        let member = format!("files/{rel}");
        let stamp = ns.unwrap_or(0);
        let stamps = Stamps {
            modified: stamp,
            accessed: stamp,
            changed: stamp,
            birth: None,
        };
        let mut hasher = Hasher::new(self.args.md5, self.args.sha1);
        let mut tee = Tee {
            inner: Counting {
                inner: stdout,
                counter: self.ctx.progress.map(|p| &p.bytes),
                stop: Some(self.ctx.stop),
            },
            providers,
        };
        let added = self
            .container
            .add_file(&member, 0o644, &stamps, &mut tee, &mut hasher);
        if matches!(added, Err(CopyError::Source(_))) && self.ctx.stop.is_set() {
            // Stopped inside the file: the member was aborted; rclone would
            // block on the full pipe, so it is ended before it is waited for
            let _ = child.kill();
            let _ = child.wait();
            let _ = err_thread.join();
            return Err(Stopped.into());
        }
        let status = child.wait()?;
        let rclone_err = err_thread.join().unwrap_or_default();
        let size = match added {
            Ok(n) => n,
            Err(CopyError::Container(e)) => return Err(e),
            Err(CopyError::Source(err)) => {
                self.ctx.count(|p| &p.errors, 1);
                let mut item = Item::new(ItemStatus::Error, rel);
                item.kind = Some("file".into());
                item.reason = Some(format!(
                    "reading from rclone failed: {err} ({})",
                    rclone_err.trim().lines().last().unwrap_or("")
                ));
                item.times = times;
                item.metadata = entry.clone();
                self.collection.add(item)?;
                return Ok(());
            }
            Err(CopyError::Duplicate(n)) => {
                self.ctx.count(|p| &p.errors, 1);
                let mut item = Item::new(ItemStatus::Error, rel);
                item.kind = Some("file".into());
                item.reason = Some(format!("another file already has the container name {n}"));
                item.metadata = entry.clone();
                self.collection.add(item)?;
                return Ok(());
            }
        };
        let mut checks = Map::new();
        let mut problems = Vec::new();
        for (name, p) in tee.providers {
            let got = p.finish();
            let want = listed[&name].as_str().unwrap_or("").to_ascii_lowercase();
            if got == want {
                checks.insert(name, json!("match"));
            } else {
                problems.push(format!("{name} differs: listed {want}, received {got}"));
                checks.insert(name, json!({ "listed": want, "received": got }));
            }
        }
        let listed_size = entry["Size"].as_i64().unwrap_or(-1);
        if listed_size >= 0 && listed_size as u64 != size {
            problems.push(format!(
                "size differs: listed {listed_size}, received {size}"
            ));
        }
        if !status.success() {
            problems.push(format!(
                "rclone cat failed ({}); the member holds the bytes received",
                rclone_err.trim().lines().last().unwrap_or("")
            ));
        }
        let mut md = entry.clone();
        md["remote_path"] = json!(src);
        md["provider_hash_checks"] = Value::Object(checks);
        md["provider_hashes_not_checked"] = json!(not_checked);
        let mut item = Item::new(
            if problems.is_empty() {
                ItemStatus::Acquired
            } else {
                ItemStatus::Error
            },
            rel,
        );
        item.kind = Some("file".into());
        item.stored_as = Some(CONTAINER.into());
        item.member = Some(member);
        item.size = Some(size);
        item.hashes = hasher.finish();
        item.times = times;
        item.metadata = md;
        if problems.is_empty() {
            self.acquired += 1;
            self.ctx.count(|p| &p.files, 1);
        } else {
            self.mismatched += 1;
            self.ctx.count(|p| &p.errors, 1);
            item.reason = Some(problems.join("; "));
        }
        self.collection.add(item)?;
        Ok(())
    }
}

fn header(args: &CloudArgs, scope: dfcore::manifest::Scope, ctx: &RunCtx) -> Result<Header> {
    Ok(Header {
        action: AUDIT_ACTION.into(),
        case: common::case(&args.case),
        source: Source {
            kind: "rclone".into(),
            locator: args.source.clone(),
            identity: Value::Null,
            details: json!({ "rclone_args": redact_args(&args.rclone_args) }),
        },
        method: Method {
            tool: TOOL.into(),
            tool_version: VERSION.into(),
            system_revision: dfcore::release::system_revision(),
            argv: ctx.argv(),
            read_only_primitives: vec![
                "rclone lsjson and rclone cat only: both read the remote and never write".into(),
            ],
            description: Some(format!(
                "The remote listed with rclone lsjson -R --hash --metadata before and after (both listings in \
                 {CONTAINER}, changes recorded); every file decided by the scope on the listing (path, modification \
                 time) before it is read; in-scope files streamed from rclone cat into files/<path> in {CONTAINER}, \
                 hashed, and checked against every provider hash dfcollect computes (md5, sha1, quickxor, dropbox); \
                 the container is read back and every member hashed again"
            )),
        },
        scope,
        clocks: dfcore::manifest::Clocks {
            reference: common::reference_at(&args.clock, ctx.reference_entered_ns)?,
            ..Default::default()
        },
    })
}

/// What a run would take: one listing of the remote decided by the scope;
/// no file is read
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudPreview {
    /// Files the listing has
    pub listed: u64,
    /// In scope
    pub files: u64,
    pub bytes: u64,
    /// Out of scope, by reason
    pub out_of_scope: BTreeMap<String, u64>,
    /// The provider hashes the listing carries (checked by the run where dfcollect computes them)
    pub hash_types: Vec<String>,
    /// The first in-scope paths and their sizes
    pub sample: Vec<(String, u64)>,
    pub target_free: Option<u64>,
    pub stopped: Option<String>,
    pub at_ns: i128,
}

/// How many in-scope paths a preview keeps
pub const PREVIEW_SAMPLE: usize = 1000;

impl CloudPreview {
    /// For the run's footprint
    #[allow(dead_code)] // the TUI's preview hands it to the run (batch 1)
    pub fn note(&self) -> PreviewNote {
        PreviewNote {
            at_ns: self.at_ns,
            what: "a preview listed the remote with rclone lsjson before the acquisition (no file read)".into(),
        }
    }

    pub fn short_of_space(&self) -> bool {
        self.target_free.is_some_and(|f| f < self.bytes)
    }

    pub fn summary(&self) -> Value {
        json!({
            "dry_run": true,
            "listed": self.listed,
            "files": self.files,
            "bytes": self.bytes,
            "out_of_scope": self.out_of_scope,
            "hash_types": self.hash_types,
            "target_free": self.target_free,
            "short_of_space": self.short_of_space(),
            "stopped": self.stopped,
        })
    }
}

/// List the remote once and decide every file by the scope; write nothing
pub fn preview(args: &CloudArgs, ctx: &RunCtx) -> Result<CloudPreview> {
    let at_ns = dfcore::host::unix_now_ns();
    let (remote, base) = split_source(&args.source)?;
    let (_, rules) = scope_rules(args)?;
    let (_, ancestor) = common::check_output(&args.output, args.allow_tmpfs)?;
    ctx.set_phase(Phase::Listing);
    ctx.set_stage("listing the remote (rclone lsjson)");
    let target = listing_target(&remote, &base);
    let mut cmd = rclone(args);
    cmd.args(["lsjson", "-R", "--hash", "--files-only", &target]);
    let mut pv = CloudPreview {
        listed: 0,
        files: 0,
        bytes: 0,
        out_of_scope: BTreeMap::new(),
        hash_types: Vec::new(),
        sample: Vec::new(),
        target_free: common::free_bytes(&ancestor),
        stopped: None,
        at_ns,
    };
    let out = match common::output_unless_stopped(cmd, ctx.stop) {
        Ok(o) => o,
        Err(e) if e.downcast_ref::<Stopped>().is_some() => {
            pv.stopped = ctx.stop.reason().map(|(r, _)| r);
            return Ok(pv);
        }
        Err(e) => return Err(e.context("Cannot run rclone")),
    };
    if !out.status.success() {
        bail!(
            "rclone lsjson: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let entries: Vec<Value> =
        serde_json::from_slice(&out.stdout).context("rclone lsjson output is not JSON")?;
    let mut hashes = std::collections::BTreeSet::new();
    for entry in &entries {
        pv.listed += 1;
        ctx.count(|p| &p.entries, 1);
        let rel = entry["Path"].as_str().unwrap_or_default();
        let ns = entry["ModTime"]
            .as_str()
            .and_then(|t| dfcore::host::parse_rfc3339(t).ok());
        match rules.decide(&Candidate {
            path: rel,
            account: None,
            time_ns: ns,
        }) {
            Decision::InScope => {
                let size = entry["Size"].as_u64().unwrap_or(0);
                pv.files += 1;
                pv.bytes += size;
                ctx.count(|p| &p.files, 1);
                ctx.count(|p| &p.bytes, size);
                if pv.sample.len() < PREVIEW_SAMPLE {
                    pv.sample.push((rel.to_string(), size));
                }
                if let Some(h) = entry["Hashes"].as_object() {
                    hashes.extend(
                        h.iter()
                            .filter(|(_, v)| v.as_str().is_some_and(|s| !s.is_empty()))
                            .map(|(k, _)| k.clone()),
                    );
                }
            }
            Decision::OutOfScope(reason) => {
                ctx.count(|p| &p.out_of_scope, 1);
                *pv.out_of_scope.entry(reason).or_default() += 1;
            }
        }
    }
    pv.hash_types = hashes.into_iter().collect();
    ctx.set_phase(Phase::Done);
    Ok(pv)
}

pub fn run_with(args: &CloudArgs, ctx: &RunCtx) -> Result<Outcome> {
    let (remote, base) = split_source(&args.source)?;
    let (scope, rules) = scope_rules(args)?;
    let (output, _) = common::check_output(&args.output, args.allow_tmpfs)?;

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
    let mut session = Session {
        args,
        ctx,
        remote,
        base,
        rules,
        collection,
        container,
        acquired: 0,
        mismatched: 0,
    };
    let mut changes = Value::Null;
    let result = (|| -> Result<()> {
        let version = session.run_rclone(&["version"])?;
        let config = session.run_rclone(&["config", "show", &session.remote.clone()])?;
        session.collection.set_source_identity(json!({
            "rclone": String::from_utf8_lossy(&version).lines().next().unwrap_or(""),
            "remote": session.remote,
            "path": session.base,
            "config": redact_config(&String::from_utf8_lossy(&config)),
        }))?;
        ctx.set_phase(Phase::Listing);
        ctx.set_stage("listing the remote (rclone lsjson)");
        let before = session.listing("rclone/listing-before.json")?;
        ctx.set_phase(Phase::Copying);
        ctx.set_total(before.len() as u64);
        ctx.set_stage("copying (rclone cat)");
        for entry in &before {
            common::check_stop(ctx.stop)?;
            ctx.count(|p| &p.entries, 1);
            session.file(entry)?;
        }
        ctx.set_phase(Phase::Listing);
        ctx.set_stage("listing the remote again (changes during the acquisition)");
        let after = session.listing("rclone/listing-after.json")?;
        changes = listing_changes(&before, &after);
        let n = ["added", "removed", "changed"]
            .iter()
            .map(|k| changes[k].as_array().map_or(0, Vec::len))
            .sum::<usize>();
        session.collection.footprint(FootprintEntry::new(
            "remote_changes",
            json!({ "during_acquisition": changes }),
        ))?;
        if n > 0 {
            session
                .collection
                .error(format!("the remote changed during the acquisition: {n} files added, removed or changed (see the footprint)"));
        }
        Ok(())
    })();
    let Session {
        collection,
        container,
        acquired,
        mismatched,
        ..
    } = session;
    let mut stopped = common::ended(result, ctx.stop);
    if let Err(e) = container.finish() {
        stopped.get_or_insert((format!("{e:#}"), 6));
    }
    let (code, finished, _) = common::conclude(collection, &output, stopped, ctx)?;
    ctx.set_phase(Phase::Done);
    let m = &finished.manifest;
    Ok(Outcome {
        code,
        summary: json!({
            "collection": output,
            "status": m.status,
            "files": acquired,
            "files_with_problems": mismatched,
            "bytes": m.totals.bytes,
            "out_of_scope_listed": m.totals.out_of_scope,
            "out_of_scope_counted": m.totals.unlisted_out_of_scope.values().sum::<u64>(),
            "errors": m.totals.errors,
            "problems": m.errors,
            "remote_changes": changes,
            "audit_anchor": m.audit_anchor,
            "warnings": finished.warnings,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_and_paths() {
        assert_eq!(split_source("drive:").unwrap(), ("drive".into(), "".into()));
        assert_eq!(
            split_source("od:Docs/2026/").unwrap(),
            ("od".into(), "Docs/2026".into())
        );
        assert!(split_source("/media/x").is_err());
        assert!(split_source(":local").is_err());
        assert_eq!(remote_path("od", "", "a/b.txt"), "od:a/b.txt");
        assert_eq!(remote_path("od", "Docs", "a.txt"), "od:Docs/a.txt");
        // Absolute paths (local, sftp) keep their leading '/'; the root stays the root
        assert_eq!(
            split_source("local:/media/share/").unwrap(),
            ("local".into(), "/media/share".into())
        );
        assert_eq!(split_source("sftp:/").unwrap(), ("sftp".into(), "/".into()));
        assert_eq!(
            remote_path("local", "/media/share", "a.txt"),
            "local:/media/share/a.txt"
        );
        assert_eq!(remote_path("sftp", "/", "etc/x"), "sftp:/etc/x");
        assert_eq!(listing_target("sftp", "/"), "sftp:/");
        assert_eq!(listing_target("od", "Docs"), "od:Docs");
        assert_eq!(listing_target("drive", ""), "drive:");
    }

    #[test]
    fn secrets_are_removed() {
        let cfg = "[od]\ntype = onedrive\ntoken = {\"access_token\":\"x\"}\nclient_secret = s\ndrive_type = business\naccess_key_id = AK\nsas_url = https://x?sig=SIG\n";
        let r = redact_config(cfg);
        assert!(
            !r.contains("access_token")
                && !r.contains("= s\n")
                && !r.contains("AK")
                && !r.contains("SIG"),
            "{r}"
        );
        assert!(r.contains("drive_type = business"), "{r}");
        let a: Vec<String> = [
            "--drive-client-secret",
            "xyz",
            "--s3-secret-access-key=abc",
            "--fast-list",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            redact_args(&a),
            vec![
                "--drive-client-secret",
                "<removed>",
                "--s3-secret-access-key=<removed>",
                "--fast-list"
            ]
        );
    }

    #[test]
    fn changes_between_listings() {
        let e = |id: &str, size: i64| json!({ "ID": id, "Path": format!("{id}.txt"), "Size": size, "ModTime": "2026-01-01T00:00:00Z", "Hashes": {} });
        let c = listing_changes(&[e("a", 1), e("b", 2)], &[e("a", 1), e("b", 3), e("c", 4)]);
        assert_eq!(c["added"].as_array().unwrap().len(), 1);
        assert_eq!(c["removed"].as_array().unwrap().len(), 0);
        assert_eq!(c["changed"].as_array().unwrap().len(), 1);
    }
}
