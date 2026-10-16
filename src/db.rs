//! `dfcollect db`: consistent logical dumps of a database server, made with
//! the database's own tools and streamed into the container, with the
//! server's version, clock, time zone, databases and sessions recorded.
//!
//! - PostgreSQL: `pg_dump --format=custom` per database (one snapshot each,
//!   in a read-only transaction) and `pg_dumpall --globals-only` (roles,
//!   tablespaces).
//! - MariaDB/MySQL: `mariadb-dump --single-transaction --routines --triggers
//!   --events --hex-blob` per database (InnoDB without locks).
//!   `--binlog-position` adds the binary-log coordinates, which costs a brief
//!   global read lock.
//! - The password goes to the tools in a 0600 file in a private directory in
//!   RAM, never on the command line or the target drive.
//! - A logical dump shows the current state only. Deleted rows survive in data
//!   files and in WAL/binlog, which come with a file-level copy or the disk
//!   image; the record says so.

use crate::{
    args::DbArgs,
    common,
    container::{Container, CopyError, Hasher},
    files::CONTAINER,
    mail::{first_line, prompt_secret},
    meta::Stamps,
    TOOL, VERSION,
};
use anyhow::{bail, Context, Result};
use dfcore::manifest::{
    Collection, Completion, FootprintEntry, Header, Item, ItemStatus, Method, Scope, Source,
};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
};

const AUDIT_ACTION: &str = "database_acquisition";

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Engine {
    Postgres,
    Mariadb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Tls {
    /// Use TLS if the server offers it (PostgreSQL `prefer`; MariaDB's default)
    Prefer,
    /// No TLS (test setups)
    Off,
    /// TLS required, certificate not checked
    Require,
    /// TLS required and the server certificate checked against the system CAs
    Verify,
}

pub struct Outcome {
    pub code: u8,
    pub summary: Value,
}

/// A private directory in RAM for the password file, removed on drop
struct Secrets {
    dir: PathBuf,
}

impl Secrets {
    fn new() -> Result<Self> {
        let base = Path::new("/dev/shm");
        let base = if base.is_dir() {
            base.to_path_buf()
        } else {
            std::env::temp_dir()
        };
        let dir = base.join(format!("dfcollect-db-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(Self { dir })
    }

    fn write(&self, name: &str, data: &str) -> Result<PathBuf> {
        let p = self.dir.join(name);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)?;
        f.write_all(data.as_bytes())?;
        Ok(p)
    }
}

impl Drop for Secrets {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A `.pgpass` line: host:port:*:user:password with `:` and `\` escaped
pub fn pgpass_line(host: &str, port: u16, user: &str, password: &str) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace(':', "\\:");
    format!("{}:{port}:*:{}:{}\n", esc(host), esc(user), esc(password))
}

/// A MariaDB option file with the client password
pub fn mycnf(password: &str) -> String {
    format!(
        "[client]\npassword=\"{}\"\n",
        password.replace('\\', "\\\\").replace('"', "\\\"")
    )
}

/// Tab-separated rows of a client's batch output
pub fn rows(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

/// A database name as a container member name
pub fn member_name(db: &str) -> String {
    db.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

struct Session<'a> {
    args: &'a DbArgs,
    collection: Collection,
    container: Container,
    env: Vec<(String, String)>,
    base_args: Vec<String>,
    dumps: u64,
    failed: u64,
}

impl Session<'_> {
    fn command(&self, program: &str) -> Command {
        let mut c = Command::new(program);
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c.args(&self.base_args);
        c
    }

    /// A query through the engine's client; tab-separated rows
    fn query(&mut self, sql: &str, db: Option<&str>) -> Result<Vec<Vec<String>>> {
        let (program, args): (&str, Vec<String>) = match self.args.engine {
            Engine::Postgres => (
                "psql",
                vec![
                    "-X".into(),
                    "-A".into(),
                    "-t".into(),
                    "-F".into(),
                    "\t".into(),
                    "-v".into(),
                    "ON_ERROR_STOP=1".into(),
                    "-d".into(),
                    db.unwrap_or("postgres").into(),
                    "-c".into(),
                    sql.into(),
                ],
            ),
            // (mariadb-dump has no --connect-timeout, so only the client gets it)
            Engine::Mariadb => (
                "mariadb",
                vec![
                    "--connect-timeout=30".into(),
                    "-N".into(),
                    "-B".into(),
                    "-e".into(),
                    sql.into(),
                ],
            ),
        };
        let out = self
            .command(program)
            .args(&args)
            .output()
            .with_context(|| format!("Cannot run {program}"))?;
        self.collection.footprint(FootprintEntry::new(
            "query",
            json!({ "client": program, "sql": sql, "exit": out.status.code() }),
        ))?;
        if !out.status.success() {
            bail!("{program}: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(rows(&String::from_utf8_lossy(&out.stdout)))
    }

    fn server(&mut self) -> Result<(Value, Vec<String>)> {
        match self.args.engine {
            Engine::Postgres => {
                let r = self.query(
                    "select version(), current_setting('TimeZone'), now(), current_setting('server_version_num'), \
                     coalesce(inet_server_addr()::text, ''), coalesce(inet_server_port()::text, ''), current_user, \
                     pg_postmaster_start_time()",
                    None,
                )?;
                let f = r.first().cloned().unwrap_or_default();
                let g = |i: usize| f.get(i).cloned().unwrap_or_default();
                let dbs = self.query(
                    "select datname, pg_database_size(datname), pg_encoding_to_char(encoding), datcollate \
                     from pg_database where datallowconn and not datistemplate order by 1",
                    None,
                )?;
                let sessions = self.query("select count(*) from pg_stat_activity", None)?;
                Ok((
                    json!({
                        "version": g(0), "time_zone": g(1), "server_now": g(2), "version_num": g(3),
                        "address": g(4), "port": g(5), "user": g(6), "started": g(7),
                        "databases": dbs.iter().map(|d| json!({ "name": d.first(), "bytes": d.get(1), "encoding": d.get(2), "collation": d.get(3) })).collect::<Vec<_>>(),
                        "sessions": sessions.first().and_then(|r| r.first()).cloned(),
                    }),
                    dbs.iter().filter_map(|d| d.first().cloned()).collect(),
                ))
            }
            Engine::Mariadb => {
                let r = self.query(
                    "select version(), @@global.time_zone, @@system_time_zone, now(6), @@hostname, current_user(), @@port",
                    None,
                )?;
                let f = r.first().cloned().unwrap_or_default();
                let g = |i: usize| f.get(i).cloned().unwrap_or_default();
                let dbs = self.query("show databases", None)?;
                let sessions =
                    self.query("select count(*) from information_schema.processlist", None)?;
                let names: Vec<String> = dbs
                    .iter()
                    .filter_map(|d| d.first().cloned())
                    .filter(|d| {
                        !["information_schema", "performance_schema", "sys"].contains(&d.as_str())
                    })
                    .collect();
                Ok((
                    json!({
                        "version": g(0), "time_zone": g(1), "system_time_zone": g(2), "server_now": g(3),
                        "hostname": g(4), "user": g(5), "port": g(6), "databases": names,
                        "sessions": sessions.first().and_then(|r| r.first()).cloned(),
                    }),
                    names,
                ))
            }
        }
    }

    /// Stream one dump tool's output into the container
    fn dump(
        &mut self,
        program: &str,
        args: &[String],
        member: &str,
        path: &str,
        md: Value,
    ) -> Result<()> {
        let mut child = self
            .command(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("Cannot run {program}"))?;
        let mut stdout = child.stdout.take().context("stdout")?;
        let mut stderr = child.stderr.take().context("stderr")?;
        let err_thread = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            s
        });
        let now = dfcore::host::unix_now_ns();
        let stamps = Stamps {
            modified: now,
            accessed: now,
            changed: now,
            birth: None,
        };
        let mut hasher = Hasher::new(self.args.md5, self.args.sha1);
        let added = self
            .container
            .add_file(member, 0o644, &stamps, &mut stdout, &mut hasher);
        let status = child.wait()?;
        let err = err_thread.join().unwrap_or_default();
        let command = format!("{program} {}", args.join(" "));
        self.collection.footprint(FootprintEntry::new(
            "dump",
            json!({ "command": command, "exit": status.code(), "stderr": err.lines().rev().take(10).collect::<Vec<_>>() }),
        ))?;
        let size = match added {
            Ok(n) => n,
            Err(CopyError::Container(e)) => return Err(e),
            Err(CopyError::Source(e)) => bail!("reading from {program}: {e}"),
            Err(CopyError::Duplicate(n)) => bail!("{n} is in the container already"),
        };
        let mut item = Item::new(
            if status.success() {
                ItemStatus::Acquired
            } else {
                ItemStatus::Error
            },
            path,
        );
        item.kind = Some("database_dump".into());
        item.stored_as = Some(CONTAINER.into());
        item.member = Some(member.into());
        item.size = Some(size);
        item.hashes = hasher.finish();
        let mut md = md;
        md["command"] = json!(command);
        item.metadata = md;
        if status.success() {
            self.dumps += 1;
        } else {
            self.failed += 1;
            item.reason = Some(format!(
                "{program} exited with {:?}: {}; the member holds what it wrote",
                status.code(),
                err.trim().lines().last().unwrap_or("")
            ));
        }
        self.collection.add(item)?;
        Ok(())
    }
}

fn header(args: &DbArgs) -> Result<Header> {
    let engine = match args.engine {
        Engine::Postgres => "postgresql",
        Engine::Mariadb => "mariadb",
    };
    Ok(Header {
        action: AUDIT_ACTION.into(),
        case: common::case(&args.case),
        source: Source {
            kind: engine.into(),
            locator: format!("{engine}://{}@{}:{}", args.user, args.host, port(args)),
            identity: Value::Null,
            details: json!({ "tls": format!("{:?}", args.tls), "databases": args.databases }),
        },
        method: Method {
            tool: TOOL.into(),
            tool_version: VERSION.into(),
            system_revision: dfcore::release::system_revision(),
            argv: std::env::args().collect(),
            read_only_primitives: match args.engine {
                Engine::Postgres => vec![
                    "pg_dump: one read-only snapshot per database (ACCESS SHARE locks: DDL waits while it runs)".into(),
                    "pg_dumpall --globals-only".into(),
                ],
                Engine::Mariadb => vec![
                    "mariadb-dump --single-transaction (consistent for InnoDB, no locks; MyISAM tables are not consistent)".into(),
                ],
            },
            description: Some(format!(
                "Server version, clock, time zone, databases and sessions queried with the engine's client; every \
                 database dumped with the engine's own tool, streamed into {CONTAINER} and hashed; a logical dump shows \
                 the current state only: deleted rows survive in data files and WAL/binlog, which need a file-level \
                 copy or the disk image; the container is read back and every member hashed again"
            )),
        },
        scope: Scope {
            legal_basis: args.legal_basis.clone(),
            include: args.databases.clone(),
            ..Scope::default()
        },
        clocks: dfcore::manifest::Clocks {
            reference: common::reference(&args.clock)?,
            ..Default::default()
        },
    })
}

fn port(args: &DbArgs) -> u16 {
    args.port.unwrap_or(match args.engine {
        Engine::Postgres => 5432,
        Engine::Mariadb => 3306,
    })
}

pub fn run(args: &DbArgs, stop: &AtomicBool) -> Result<Outcome> {
    let (output, _) = common::check_output(&args.output, args.allow_tmpfs)?;
    let password = match &args.password_file {
        Some(p) => Some(first_line(p)?),
        None if args.no_password => None,
        None => Some(prompt_secret("Database password: ")?),
    };
    let port = port(args);
    let secrets = Secrets::new()?;
    let mut env = Vec::new();
    let mut base_args: Vec<String> = Vec::new();
    match args.engine {
        Engine::Postgres => {
            env.push(("PGHOST".into(), args.host.clone()));
            env.push(("PGPORT".into(), port.to_string()));
            env.push(("PGUSER".into(), args.user.clone()));
            env.push(("PGCONNECT_TIMEOUT".into(), "30".into()));
            env.push((
                "PGSSLMODE".into(),
                match args.tls {
                    Tls::Prefer => "prefer",
                    Tls::Off => "disable",
                    Tls::Require => "require",
                    Tls::Verify => "verify-full",
                }
                .into(),
            ));
            if args.tls == Tls::Verify {
                env.push(("PGSSLROOTCERT".into(), "system".into()));
            }
            let pass = match &password {
                Some(pw) => {
                    secrets.write("pgpass", &pgpass_line(&args.host, port, &args.user, pw))?
                }
                None => secrets.write("pgpass", "")?,
            };
            env.push(("PGPASSFILE".into(), pass.display().to_string()));
            base_args.push("--no-password".into());
        }
        Engine::Mariadb => {
            let cnf = secrets.write("my.cnf", &mycnf(password.as_deref().unwrap_or("")))?;
            // --defaults-extra-file must come first
            base_args.push(format!("--defaults-extra-file={}", cnf.display()));
            base_args.extend([
                format!("--host={}", args.host),
                format!("--port={port}"),
                format!("--user={}", args.user),
                "--protocol=TCP".into(),
            ]);
            // MariaDB 11.4's client defaults to TLS with certificate checks
            // (MDEV-31855), so prefer and require switch the checks off
            match args.tls {
                Tls::Prefer => base_args.push("--skip-ssl-verify-server-cert".into()),
                Tls::Off => base_args.push("--skip-ssl".into()),
                Tls::Require => {
                    base_args.extend(["--ssl".into(), "--skip-ssl-verify-server-cert".into()])
                }
                Tls::Verify => {
                    base_args.extend(["--ssl".into(), "--ssl-verify-server-cert".into()])
                }
            }
        }
    }

    let collection = Collection::create(&output, header(args)?)?;
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
        collection,
        container,
        env,
        base_args,
        dumps: 0,
        failed: 0,
    };
    let result = (|| -> Result<()> {
        let (server, all) = session.server()?;
        session.collection.set_source_identity(server)?;
        let wanted: Vec<String> = if args.databases.is_empty() {
            all.clone()
        } else {
            for d in &args.databases {
                if !all.contains(d) {
                    bail!(
                        "the server has no database {d} (it has: {})",
                        all.join(", ")
                    );
                }
            }
            args.databases.clone()
        };
        for d in all.iter().filter(|d| !wanted.contains(d)) {
            session
                .collection
                .count_out_of_scope(&format!("database {d} not named with --database"));
        }
        match args.engine {
            Engine::Postgres => {
                // Role password hashes need a superuser and are rarely in scope
                session.dump(
                    "pg_dumpall",
                    &["--globals-only".into(), "--no-role-passwords".into()],
                    "postgres/globals.sql",
                    "globals",
                    json!({ "what": "roles and tablespaces, without role password hashes" }),
                )?;
                for db in &wanted {
                    if stop.load(Ordering::Relaxed) {
                        bail!("stopped by a signal");
                    }
                    let mut a = vec!["--format=custom".to_string()];
                    if args.serializable {
                        a.push("--serializable-deferrable".into());
                    }
                    a.extend(["-d".to_string(), db.clone()]);
                    session.dump(
                        "pg_dump",
                        &a,
                        &format!("postgres/{}.dump", member_name(db)),
                        db,
                        json!({ "database": db, "format": "pg_dump custom (pg_restore)" }),
                    )?;
                }
            }
            Engine::Mariadb => {
                for db in &wanted {
                    if stop.load(Ordering::Relaxed) {
                        bail!("stopped by a signal");
                    }
                    let mut a: Vec<String> = [
                        "--single-transaction",
                        "--routines",
                        "--triggers",
                        "--events",
                        "--hex-blob",
                        "--skip-dump-date",
                    ]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                    if args.binlog_position {
                        a.push("--master-data=2".into());
                    }
                    a.extend(["--databases".to_string(), db.clone()]);
                    session.dump(
                        "mariadb-dump",
                        &a,
                        &format!("mariadb/{}.sql", member_name(db)),
                        db,
                        json!({ "database": db, "format": "SQL" }),
                    )?;
                }
            }
        }
        Ok(())
    })();
    let Session {
        collection,
        container,
        dumps,
        failed,
        ..
    } = session;
    drop(secrets);
    let mut stopped = match result {
        Ok(()) => None,
        Err(e) if stop.load(Ordering::Relaxed) => Some((format!("{e:#}"), 8)),
        Err(e) => Some((format!("{e:#}"), 6)),
    };
    if let Err(e) = container.finish() {
        stopped.get_or_insert((format!("{e:#}"), 6));
    }
    let (code, finished, _) = common::conclude(collection, &output, stopped)?;
    let m = &finished.manifest;
    Ok(Outcome {
        code,
        summary: json!({
            "collection": output,
            "status": m.status,
            "dumps": dumps,
            "failed": failed,
            "bytes": m.totals.bytes,
            "errors": m.totals.errors,
            "problems": m.errors,
            "audit_anchor": m.audit_anchor,
            "warnings": finished.warnings,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_files() {
        assert_eq!(
            pgpass_line("db", 5432, "u", "p:a\\ss"),
            "db:5432:*:u:p\\:a\\\\ss\n"
        );
        assert_eq!(mycnf("a\"b"), "[client]\npassword=\"a\\\"b\"\n");
    }

    #[test]
    fn output_parsing_and_names() {
        assert_eq!(rows("a\tb\n\nc\td\n"), vec![vec!["a", "b"], vec!["c", "d"]]);
        assert_eq!(member_name("shop db/1"), "shop_db_1");
        assert_eq!(member_name("../x"), ".._x");
    }
}
