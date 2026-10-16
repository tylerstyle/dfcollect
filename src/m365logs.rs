//! `dfcollect m365-logs`: the logs of a Microsoft 365 tenant for a time
//! window, through Microsoft Graph, usually with the tenant's cooperation:
//!
//! - Entra sign-in logs (`auditLogs/signIns`; needs Entra ID P1/P2, kept 30
//!   days);
//! - Entra directory audits (`auditLogs/directoryAudits`);
//! - the Unified Audit Log (Purview Audit) through the audit log query API.
//!   A query is created in the tenant with a POST, which is the only write
//!   (it is recorded); its records are read when it has run.
//!
//! Each log becomes one JSON Lines member of the container
//! (`logs/<name>.jsonl`, one record per line as Graph returned it), with its
//! record count, filters and time window in its item. A log the tenant
//! refuses (licence, permission) fails as one item; the others are still read.

use crate::{
    args::M365LogsArgs,
    common,
    container::{Container, CopyError, Hasher},
    files::CONTAINER,
    graph::{check_endpoints, flow, Api},
    http::{encode, Client},
    meta::Stamps,
    oauth::Auth,
    Usage, TOOL, VERSION,
};
use anyhow::{bail, Context, Result};
use dfcore::manifest::{
    Collection, Completion, FootprintEntry, Header, Item, ItemStatus, Method, Scope, Source,
};
use serde_json::{json, Value};
use std::{
    io::{BufWriter, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const AUDIT_ACTION: &str = "cloud_log_acquisition";
const PAGE: u32 = 999;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum LogKind {
    /// Entra sign-in logs
    Signins,
    /// Entra directory audits
    Directory,
    /// The Unified Audit Log (Purview Audit), through an audit log query
    Ual,
}

impl LogKind {
    fn name(self) -> &'static str {
        match self {
            LogKind::Signins => "signins",
            LogKind::Directory => "directory-audits",
            LogKind::Ual => "unified-audit-log",
        }
    }

    /// Delegated permissions a device-code sign-in needs for this log
    fn scopes(self) -> &'static [&'static str] {
        match self {
            LogKind::Signins => &["AuditLog.Read.All", "Directory.Read.All"],
            LogKind::Directory => &["AuditLog.Read.All"],
            LogKind::Ual => &["AuditLogsQuery.Read.All"],
        }
    }
}

pub struct Outcome {
    pub code: u8,
    pub summary: Value,
}

/// An OData string literal
fn quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// `field ge FROM and field lt TO [and (user eq 'a' or user eq 'b')]`
pub fn time_filter(
    field: &str,
    from: &str,
    to: &str,
    user_field: &str,
    users: &[String],
) -> String {
    let mut f = format!("{field} ge {from} and {field} lt {to}");
    if !users.is_empty() {
        let any: Vec<String> = users
            .iter()
            .map(|u| format!("{user_field} eq {}", quoted(u)))
            .collect();
        f.push_str(&format!(" and ({})", any.join(" or ")));
    }
    f
}

/// RFC 3339 → whole seconds in UTC: the start rounded down, the end up, so
/// the window never shrinks
fn window(not_before: &str, not_after: &str) -> Result<(String, String)> {
    let nb = dfcore::host::parse_rfc3339(not_before)
        .map_err(|e| Usage(format!("--not-before: {e:#}")))?;
    let na =
        dfcore::host::parse_rfc3339(not_after).map_err(|e| Usage(format!("--not-after: {e:#}")))?;
    if nb >= na {
        return Err(Usage("--not-before must be before --not-after".into()).into());
    }
    let s = 1_000_000_000i128;
    let from = nb.div_euclid(s);
    let to = na.div_euclid(s) + i128::from(na.rem_euclid(s) != 0);
    let fmt = |t: i128| dfcore::host::rfc3339_utc(u64::try_from(t).unwrap_or(0));
    Ok((fmt(from), fmt(to)))
}

struct Session<'a> {
    args: &'a M365LogsArgs,
    api: Api,
    v1: String,
    collection: Collection,
    container: Container,
    output: &'a Path,
    stop: &'a AtomicBool,
    from: String,
    to: String,
    records: u64,
}

impl Session<'_> {
    /// Write records page by page into a temporary file on the target, then
    /// into the container as one member
    fn store(
        &mut self,
        kind: LogKind,
        mut fill: impl FnMut(&mut Api, &mut dyn FnMut(&[Value]) -> Result<()>) -> Result<()>,
        metadata: Value,
    ) -> Result<()> {
        let name = kind.name();
        let tmp = self.output.join(format!(".{name}.jsonl.part"));
        let mut count = 0u64;
        let written = (|| -> Result<()> {
            let mut w = BufWriter::new(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp)
                    .with_context(|| format!("Cannot create {}", tmp.display()))?,
            );
            fill(&mut self.api, &mut |page: &[Value]| {
                for r in page {
                    serde_json::to_writer(&mut w, r)?;
                    w.write_all(b"\n")?;
                    count += 1;
                }
                Ok(())
            })?;
            w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
            Ok(())
        })();
        let path = format!("logs/{name}");
        let mut md = metadata;
        md["log"] = json!(name);
        md["window"] = json!({ "from": self.from, "to": self.to });
        md["users"] = json!(self.args.users);
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            if self.stop.load(Ordering::Relaxed) {
                return Err(e);
            }
            let mut item = Item::new(ItemStatus::Error, path);
            item.kind = Some("log".into());
            item.reason = Some(format!("{e:#}"));
            item.metadata = md;
            self.collection.add(item)?;
            eprintln!("[!] {name}: {e:#}");
            return Ok(());
        }
        let member = format!("{path}.jsonl");
        let now = dfcore::host::unix_now_ns();
        let stamps = Stamps {
            modified: now,
            accessed: now,
            changed: now,
            birth: None,
        };
        let mut hasher = Hasher::new(self.args.md5, self.args.sha1);
        let mut file = std::fs::File::open(&tmp)?;
        let size = match self
            .container
            .add_file(&member, 0o644, &stamps, &mut file, &mut hasher)
        {
            Ok(n) => n,
            Err(CopyError::Container(e)) => return Err(e),
            Err(CopyError::Source(e)) => return Err(e.into()),
            Err(CopyError::Duplicate(n)) => bail!("{n} is in the container already"),
        };
        std::fs::remove_file(&tmp)?;
        md["records"] = json!(count);
        self.records += count;
        let mut item = Item::new(ItemStatus::Acquired, path);
        item.kind = Some("log".into());
        item.stored_as = Some(CONTAINER.into());
        item.member = Some(member);
        item.size = Some(size);
        item.hashes = hasher.finish();
        item.metadata = md;
        self.collection.add(item)?;
        println!("[✓] {name}: {count} records");
        Ok(())
    }

    fn entra(&mut self, kind: LogKind) -> Result<()> {
        let (path, field, user_field) = match kind {
            LogKind::Signins => ("auditLogs/signIns", "createdDateTime", "userPrincipalName"),
            _ => (
                "auditLogs/directoryAudits",
                "activityDateTime",
                "initiatedBy/user/userPrincipalName",
            ),
        };
        let filter = time_filter(field, &self.from, &self.to, user_field, &self.args.users);
        let url = format!("{}/{path}?$filter={}&$top={PAGE}", self.v1, encode(&filter));
        let stop = self.stop;
        let mut pages = 0;
        let md = json!({ "endpoint": format!("/v1.0/{path}"), "filter": filter });
        self.store(
            kind,
            |api, sink| {
                pages = api.each_page(&url, stop, |p| sink(p))?;
                Ok(())
            },
            md,
        )?;
        self.collection.footprint(FootprintEntry::new(
            "request",
            json!({ "request": format!("GET /v1.0/{path}"), "filter": filter, "pages": pages }),
        ))
    }

    fn ual(&mut self) -> Result<()> {
        let mut body = json!({
            "@odata.type": "#microsoft.graph.security.auditLogQuery",
            "displayName": format!(
                "dfcollect {} {} {}",
                self.args.case.case, self.args.case.evidence, self.from
            ),
            "filterStartDateTime": self.from,
            "filterEndDateTime": self.to,
        });
        if !self.args.users.is_empty() {
            body["userPrincipalNameFilters"] = json!(self.args.users);
        }
        if !self.args.record_types.is_empty() {
            body["recordTypeFilters"] = json!(self.args.record_types);
        }
        if !self.args.operations.is_empty() {
            body["operationFilters"] = json!(self.args.operations);
        }
        let poll = Duration::from_secs(self.args.ual_poll.max(1));
        let deadline = Instant::now() + Duration::from_secs(self.args.ual_wait * 60);
        let stop = self.stop;
        let base = self.v1.clone();
        let mut record = json!({ "query": body });
        let created = (|| -> Result<(String, String)> {
            let url = format!("{base}/security/auditLog/queries");
            let q = self.api.post_json(&url, &body)?;
            let id = q["id"]
                .as_str()
                .context("the audit log query has no id")?
                .to_string();
            Ok((id, url))
        })();
        let (id, queries) = match created {
            Ok(v) => v,
            Err(e) => {
                record["error"] = json!(format!("{e:#}"));
                self.collection
                    .footprint(FootprintEntry::new("audit_log_query", record.clone()))?;
                let mut item = Item::new(ItemStatus::Error, "logs/unified-audit-log");
                item.kind = Some("log".into());
                item.reason = Some(format!("creating the audit log query: {e:#}"));
                item.metadata = record;
                self.collection.add(item)?;
                eprintln!("[!] unified-audit-log: {e:#}");
                return Ok(());
            }
        };
        record["id"] = json!(id);
        record["created_with"] = json!("POST /v1.0/security/auditLog/queries");
        self.collection.footprint(FootprintEntry::new(
            "audit_log_query",
            json!({ "created": record, "note": "an audit log search now exists in the tenant (Purview Audit)" }),
        ))?;
        println!("[*] Audit log query {id} created; waiting for it to run");
        let status_url = format!("{queries}/{}", encode(&id));
        let mut polls = 0u32;
        let status = loop {
            if stop.load(Ordering::Relaxed) {
                bail!("stopped by a signal");
            }
            let q = self.api.get_json(&status_url)?;
            polls += 1;
            let s = q["status"].as_str().unwrap_or("").to_string();
            if matches!(s.as_str(), "succeeded" | "failed" | "cancelled") {
                break s;
            }
            if Instant::now() > deadline {
                break format!("still {s} after {} min", self.args.ual_wait);
            }
            std::thread::sleep(poll);
        };
        self.collection.footprint(FootprintEntry::new(
            "audit_log_query",
            json!({ "id": id, "status": status, "polls": polls }),
        ))?;
        let mut md = json!({
            "endpoint": "/v1.0/security/auditLog/queries",
            "query_id": id,
            "query": body,
            "status": status,
        });
        if status != "succeeded" {
            let mut item = Item::new(ItemStatus::Error, "logs/unified-audit-log");
            item.kind = Some("log".into());
            item.reason = Some(format!("the audit log query {id} ended {status}"));
            md["window"] = json!({ "from": self.from, "to": self.to });
            item.metadata = md;
            self.collection.add(item)?;
            eprintln!("[!] unified-audit-log: query {status}");
            return Ok(());
        }
        let url = format!("{status_url}/records?$top=1000");
        md["endpoint"] = json!(format!("/v1.0/security/auditLog/queries/{id}/records"));
        self.store(
            LogKind::Ual,
            |api, sink| {
                api.each_page(&url, stop, |p| sink(p))?;
                Ok(())
            },
            md,
        )
    }
}

fn header(args: &M365LogsArgs, from: &str, to: &str) -> Result<Header> {
    let graph = args.conn.graph_endpoint.trim_end_matches('/');
    let logs: Vec<&str> = args.logs.iter().map(|l| l.name()).collect();
    Ok(Header {
        action: AUDIT_ACTION.into(),
        case: common::case(&args.case),
        source: Source {
            kind: "microsoft-graph".into(),
            locator: format!("{graph}/v1.0 (tenant {}) logs {}", args.conn.tenant, logs.join(", ")),
            identity: Value::Null,
            details: Value::Null,
        },
        method: Method {
            tool: TOOL.into(),
            tool_version: VERSION.into(),
            system_revision: dfcore::release::system_revision(),
            argv: std::env::args().collect(),
            read_only_primitives: vec![
                "sign-in and directory logs: GET only".into(),
                "Unified Audit Log: one audit log query created in the tenant (POST /security/auditLog/queries), then GET".into(),
            ],
            description: Some(format!(
                "Logs of the window [{from}, {to}) read through Microsoft Graph, filtered on the server by time \
                 and, if given, by account; every record stored as one JSON line in logs/<log>.jsonl in \
                 {CONTAINER}; the container is read back and every member hashed again"
            )),
        },
        scope: Scope {
            legal_basis: args.legal_basis.clone(),
            accounts: args.users.clone(),
            not_before: Some(from.to_string()),
            not_after: Some(to.to_string()),
            time_basis: Some("createdDateTime (sign-ins, audit log), activityDateTime (directory audits)".into()),
            ..Scope::default()
        },
        clocks: dfcore::manifest::Clocks {
            reference: common::reference(&args.clock)?,
            ..Default::default()
        },
    })
}

pub fn run(args: &M365LogsArgs, stop: &AtomicBool) -> Result<Outcome> {
    if args.logs.is_empty() {
        return Err(Usage("--logs names no log".into()).into());
    }
    check_endpoints(&args.conn)?;
    let (from, to) = window(&args.not_before, &args.not_after)?;
    let (output, _) = common::check_output(&args.output, args.allow_tmpfs)?;
    let flow = flow(&args.conn)?;
    let graph = args.conn.graph_endpoint.trim_end_matches('/').to_string();
    let mut scopes: Vec<&str> = args
        .logs
        .iter()
        .flat_map(|l| l.scopes().iter().copied())
        .collect();
    scopes.sort_unstable();
    scopes.dedup();

    let mut collection = Collection::create(&output, header(args, &from, &to)?)?;
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
    let (auth, record) =
        match Auth::sign_in(&mut http, flow, &args.conn.login_endpoint, &graph, &scopes) {
            Ok(a) => a,
            Err(e) => {
                let reason = format!("{e:#}");
                collection.footprint(FootprintEntry::new("auth", json!({ "error": reason })))?;
                container.finish()?;
                let (code, finished, _) = common::conclude(collection, &output, Some((reason, 4)))?;
                return Ok(Outcome {
                    code,
                    summary: summary(&output, &finished, 0),
                });
            }
        };
    collection.footprint(FootprintEntry::new("auth", record.clone()))?;
    collection.set_source_identity(json!({ "auth": record, "tenant": args.conn.tenant }))?;

    let mut session = Session {
        args,
        api: Api {
            http,
            auth,
            graph: graph.clone(),
        },
        v1: format!("{graph}/v1.0"),
        collection,
        container,
        output: &output,
        stop,
        from,
        to,
        records: 0,
    };
    let result = (|| -> Result<()> {
        for kind in &args.logs {
            if stop.load(Ordering::Relaxed) {
                bail!("stopped by a signal");
            }
            match kind {
                LogKind::Ual => session.ual()?,
                k => session.entra(*k)?,
            }
        }
        Ok(())
    })();
    let Session {
        mut collection,
        container,
        api: Api { http, auth, .. },
        records,
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
                "records": records,
                "tls": http.tls.iter().map(|(h, t)| (h.clone(), json!({ "version": t.version, "cipher": t.cipher, "verified_by": t.verified_by }))).collect::<serde_json::Map<_, _>>(),
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
        summary: summary(&output, &finished, records),
    })
}

fn summary(output: &Path, finished: &dfcore::manifest::Finished, records: u64) -> Value {
    let m = &finished.manifest;
    json!({
        "collection": output,
        "status": m.status,
        "logs": m.totals.acquired,
        "records": records,
        "bytes": m.totals.bytes,
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
    fn filters_and_windows() {
        assert_eq!(
            time_filter(
                "createdDateTime",
                "2026-01-01T00:00:00Z",
                "2026-02-01T00:00:00Z",
                "userPrincipalName",
                &[]
            ),
            "createdDateTime ge 2026-01-01T00:00:00Z and createdDateTime lt 2026-02-01T00:00:00Z"
        );
        assert_eq!(
            time_filter("t", "A", "B", "upn", &["a@x".into(), "o'neil@x".into()]),
            "t ge A and t lt B and (upn eq 'a@x' or upn eq 'o''neil@x')"
        );
        assert_eq!(
            window("2026-01-01T00:00:00.5+01:00", "2026-01-02T00:00:00.1Z").unwrap(),
            ("2025-12-31T23:00:00Z".into(), "2026-01-02T00:00:01Z".into())
        );
        assert!(window("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z").is_err());
        assert!(window("yesterday", "2026-01-01T00:00:00Z").is_err());
    }

    #[test]
    fn delegated_scopes_follow_the_logs() {
        assert_eq!(LogKind::Ual.scopes(), &["AuditLogsQuery.Read.All"]);
        assert!(LogKind::Signins.scopes().contains(&"AuditLog.Read.All"));
    }
}
