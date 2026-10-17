//! `dfcollect ingest`: a data package a provider delivered (e-Evidence
//! production orders under Regulation (EU) 2023/1543, provider exports,
//! deliveries on media), taken into a verifiable collection.
//!
//! - The receipt is recorded: provider, when it was received, over which
//!   channel, the order reference, and the examiner.
//! - Every file of the package is stored in the container, as it is, and
//!   hashed.
//! - The provider's hash lists (`sha256sum`/`md5sum`/`sha1sum`/`sha512sum`
//!   output, or BSD `SHA256 (path) = …`) are stored too, and every file is
//!   checked against them. A file that differs or is missing is an error. So
//!   is a file the lists don't name, unless `--allow-unlisted`.
//! - Symlinks are recorded, not followed; other special files are errors.

use crate::{
    args::IngestArgs,
    common::{self, Counting, Phase, RunCtx, Stopped},
    container::{Container, CopyError, Hasher},
    files::CONTAINER,
    meta::Stamps,
    Usage, TOOL, VERSION,
};
use anyhow::{bail, Context, Result};
use dfcore::manifest::{
    Collection, Completion, FootprintEntry, Header, Item, ItemStatus, Method, Scope, Source, Times,
};
use serde_json::{json, Value};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const AUDIT_ACTION: &str = "provider_delivery";

pub struct Outcome {
    pub code: u8,
    pub summary: Value,
}

/// A provider's hash for one path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub algorithm: &'static str,
    pub hex: String,
    pub list: String,
}

fn algorithm_for(hex: &str) -> Option<&'static str> {
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(match hex.len() {
        32 => "md5",
        40 => "sha1",
        64 => "sha256",
        128 => "sha512",
        _ => return None,
    })
}

/// A path as written in a hash list, normalized like the package's paths
pub fn normalize(path: &str) -> String {
    let p = path.trim().replace('\\', "/");
    let p = p.trim_start_matches("./");
    p.trim_start_matches('/').to_string()
}

/// Parse one hash list: `HEX  path`, `HEX *path`, or `ALG (path) = HEX`
pub fn parse_list(text: &str, list: &str) -> Result<BTreeMap<String, Vec<Listed>>> {
    let mut out: BTreeMap<String, Vec<Listed>> = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let (hex, path) = if let Some((head, hex)) = line.rsplit_once(") = ") {
            // BSD style
            let Some((_, path)) = head.split_once(" (") else {
                bail!("{list}:{}: unreadable line", n + 1);
            };
            (hex.trim().to_string(), path.to_string())
        } else {
            let Some((hex, rest)) = line.split_once(char::is_whitespace) else {
                bail!("{list}:{}: unreadable line", n + 1);
            };
            let rest = rest.trim_start();
            let path = rest.strip_prefix('*').unwrap_or(rest);
            (hex.to_string(), path.to_string())
        };
        let Some(algorithm) = algorithm_for(&hex) else {
            bail!(
                "{list}:{}: {hex:?} is not an MD5, SHA-1, SHA-256 or SHA-512 value",
                n + 1
            );
        };
        out.entry(normalize(&path)).or_default().push(Listed {
            algorithm,
            hex: hex.to_ascii_lowercase(),
            list: list.to_string(),
        });
    }
    Ok(out)
}

/// Files below `root`, sorted, as (relative path, full path); symlinks and
/// special files reported with their kind
fn walk(root: &Path) -> Result<Vec<(String, PathBuf, &'static str)>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .with_context(|| format!("Cannot read {}", dir.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries.into_iter().rev() {
            let path = e.path();
            let ft = e.file_type()?;
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_symlink() {
                out.push((rel, path, "symlink"));
            } else if ft.is_file() {
                out.push((rel, path, "file"));
            } else {
                out.push((rel, path, "special"));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Hashes the provider used, alongside the container's own
struct Extra {
    md5: Option<md5::Md5>,
    sha1: Option<sha1::Sha1>,
    sha256: Option<sha2::Sha256>,
    sha512: Option<sha2::Sha512>,
}

impl Extra {
    fn for_listed(listed: &[Listed]) -> Self {
        let has = |a: &str| listed.iter().any(|l| l.algorithm == a);
        Self {
            md5: has("md5").then(md5::Md5::new),
            sha1: has("sha1").then(sha1::Sha1::new),
            sha256: has("sha256").then(sha2::Sha256::new),
            sha512: has("sha512").then(sha2::Sha512::new),
        }
    }

    fn update(&mut self, b: &[u8]) {
        if let Some(h) = &mut self.md5 {
            h.update(b);
        }
        if let Some(h) = &mut self.sha1 {
            h.update(b);
        }
        if let Some(h) = &mut self.sha256 {
            h.update(b);
        }
        if let Some(h) = &mut self.sha512 {
            h.update(b);
        }
    }

    fn finish(self) -> BTreeMap<&'static str, String> {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let mut m = BTreeMap::new();
        if let Some(h) = self.md5 {
            m.insert("md5", hex(&h.finalize()));
        }
        if let Some(h) = self.sha1 {
            m.insert("sha1", hex(&h.finalize()));
        }
        if let Some(h) = self.sha256 {
            m.insert("sha256", hex(&h.finalize()));
        }
        if let Some(h) = self.sha512 {
            m.insert("sha512", hex(&h.finalize()));
        }
        m
    }
}

struct Tee<'a, R> {
    inner: R,
    extra: &'a mut Extra,
}

impl<R: Read> Read for Tee<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.extra.update(&buf[..n]);
        Ok(n)
    }
}

fn stamps_of(md: &std::fs::Metadata) -> Stamps {
    let ns = |s: i64, n: i64| i128::from(s) * 1_000_000_000 + i128::from(n);
    Stamps {
        modified: ns(md.mtime(), md.mtime_nsec()),
        accessed: ns(md.atime(), md.atime_nsec()),
        changed: ns(md.ctime(), md.ctime_nsec()),
        birth: None,
    }
}

fn header(args: &IngestArgs, received: &str, ctx: &RunCtx) -> Result<Header> {
    Ok(Header {
        action: AUDIT_ACTION.into(),
        case: common::case(&args.case),
        source: Source {
            kind: "provider-delivery".into(),
            locator: format!(
                "{} ({})",
                args.provider,
                args.reference.as_deref().unwrap_or("no reference")
            ),
            identity: Value::Null,
            details: json!({
                "provider": args.provider,
                "received_at": received,
                "channel": args.channel,
                "reference": args.reference,
                "package": args.package,
            }),
        },
        method: Method {
            tool: TOOL.into(),
            tool_version: VERSION.into(),
            system_revision: dfcore::release::system_revision(),
            argv: ctx.argv(),
            read_only_primitives: vec!["the package is only read".into()],
            description: Some(format!(
                "Every file of the delivered package stored as package/<path> in {CONTAINER} and hashed; the \
                 provider's hash lists stored as provider/<name> and every file checked against them (differing or \
                 missing files are errors, and so are files the lists don't name unless --allow-unlisted); \
                 symlinks recorded, not followed; the container is read back and every member hashed again"
            )),
        },
        scope: Scope {
            legal_basis: args.legal_basis.clone(),
            ..Scope::default()
        },
        clocks: dfcore::manifest::Clocks {
            reference: common::reference_at(&args.clock, ctx.reference_entered_ns)?,
            ..Default::default()
        },
    })
}

pub fn run_with(args: &IngestArgs, ctx: &RunCtx) -> Result<Outcome> {
    let received = dfcore::host::parse_rfc3339(&args.received_at)
        .map(dfcore::host::rfc3339_utc_ns)
        .map_err(|e| Usage(format!("--received-at: {e:#}")))?;
    let package = std::path::absolute(&args.package)?;
    let meta = std::fs::symlink_metadata(&package)
        .with_context(|| format!("Cannot read {}", package.display()))?;
    let (output, _) = common::check_output(&args.output, args.allow_tmpfs)?;
    if output.starts_with(&package) {
        return Err(Usage("the collection directory must not be inside the package".into()).into());
    }
    // The provider's lists, read before anything is written
    let mut lists: Vec<(String, PathBuf, String)> = Vec::new();
    let mut listed: BTreeMap<String, Vec<Listed>> = BTreeMap::new();
    for p in &args.hashes {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "hashes".into());
        let text =
            std::fs::read_to_string(p).map_err(|e| Usage(format!("{}: {e}", p.display())))?;
        for (path, l) in parse_list(&text, &name).map_err(|e| Usage(format!("{e:#}")))? {
            listed.entry(path).or_default().extend(l);
        }
        lists.push((name, p.clone(), text));
    }
    let files: Vec<(String, PathBuf, &'static str)> = if meta.is_dir() {
        walk(&package)?
    } else if meta.is_file() {
        let name = package
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        vec![(name, package.clone(), "file")]
    } else {
        return Err(Usage(format!("{}: a directory or a file", package.display())).into());
    };

    let mut collection = Collection::create(&output, header(args, &received, ctx)?)?;
    let mut container = match Container::create(&output.join(CONTAINER), args.compress) {
        Ok(c) => c,
        Err(e) => {
            collection.finish(Completion::Aborted {
                reason: format!("{e:#}"),
            })?;
            return Err(e);
        }
    };
    for entry in ctx.footprint() {
        collection.footprint(entry)?;
    }
    ctx.set_phase(Phase::Copying);
    ctx.set_total(files.len() as u64);
    collection.footprint(FootprintEntry::new(
        "receipt",
        json!({
            "provider": args.provider,
            "received_at": received,
            "channel": args.channel,
            "reference": args.reference,
            "examiner": args.case.examiner,
            "hash_lists": lists.iter().map(|(n, p, _)| json!({ "name": n, "path": p })).collect::<Vec<_>>(),
        }),
    ))?;
    let mut tally = BTreeMap::from([
        ("verified", 0u64),
        ("mismatched", 0),
        ("unlisted", 0),
        ("missing", 0),
        ("errors", 0),
    ]);
    let mut seen = std::collections::BTreeSet::new();
    let result = (|| -> Result<()> {
        for (name, _, text) in &lists {
            let member = format!("provider/{name}");
            let mut hasher = Hasher::new(args.md5, args.sha1);
            let now = dfcore::host::unix_now_ns();
            let stamps = Stamps {
                modified: now,
                accessed: now,
                changed: now,
                birth: None,
            };
            match container.add_file(&member, 0o444, &stamps, &mut text.as_bytes(), &mut hasher) {
                Ok(_) => {}
                Err(CopyError::Container(e)) => return Err(e),
                Err(CopyError::Source(e)) => return Err(e.into()),
                Err(CopyError::Duplicate(n)) => bail!("two hash lists are both called {n}"),
            }
            let mut item = Item::new(ItemStatus::Acquired, member.clone());
            item.kind = Some("hash_list".into());
            item.stored_as = Some(CONTAINER.into());
            item.member = Some(member);
            item.size = Some(text.len() as u64);
            item.hashes = hasher.finish();
            collection.add(item)?;
        }
        for (rel, full, kind) in &files {
            common::check_stop(ctx.stop)?;
            ctx.set_current(rel);
            ctx.count(|p| &p.entries, 1);
            let key = normalize(rel);
            seen.insert(key.clone());
            if *kind != "file" {
                let mut item = Item::new(
                    if *kind == "symlink" {
                        ItemStatus::Acquired
                    } else {
                        ItemStatus::Error
                    },
                    rel.clone(),
                );
                item.kind = Some((*kind).into());
                if *kind == "symlink" {
                    item.metadata = json!({ "target": std::fs::read_link(full).ok() });
                } else {
                    item.reason = Some("a special file in the package".into());
                    *tally.get_mut("errors").unwrap() += 1;
                    ctx.count(|p| &p.errors, 1);
                }
                // A hash list that names it expected a file
                if let Some(l) = listed.get(&key) {
                    item.status = ItemStatus::Error;
                    item.reason = Some(format!(
                        "listed in {} as a file, but it is a {kind} in the package",
                        l.iter()
                            .map(|x| x.list.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    *tally.get_mut("mismatched").unwrap() += 1;
                }
                collection.add(item)?;
                continue;
            }
            let md = std::fs::metadata(full)?;
            let want = listed.get(&key).cloned().unwrap_or_default();
            let mut extra = Extra::for_listed(&want);
            let mut hasher = Hasher::new(args.md5, args.sha1);
            let member = format!("package/{rel}");
            let f = std::fs::File::open(full)
                .with_context(|| format!("Cannot open {}", full.display()))?;
            let added = container.add_file(
                &member,
                0o444,
                &stamps_of(&md),
                &mut Tee {
                    inner: Counting {
                        inner: f,
                        counter: ctx.progress.map(|p| &p.bytes),
                        stop: Some(ctx.stop),
                    },
                    extra: &mut extra,
                },
                &mut hasher,
            );
            let size = match added {
                Ok(n) => n,
                Err(CopyError::Container(e)) => return Err(e),
                // A stop inside a large file: the member was aborted, the file is not recorded
                Err(CopyError::Source(_)) if ctx.stop.is_set() => return Err(Stopped.into()),
                Err(CopyError::Source(e)) => {
                    ctx.count(|p| &p.errors, 1);
                    let mut item = Item::new(ItemStatus::Error, rel.clone());
                    item.kind = Some("file".into());
                    item.reason = Some(format!("reading failed: {e}"));
                    collection.add(item)?;
                    *tally.get_mut("errors").unwrap() += 1;
                    continue;
                }
                Err(CopyError::Duplicate(n)) => bail!("{n} twice in the package"),
            };
            let computed = extra.finish();
            let mut checks = Vec::new();
            let mut bad = Vec::new();
            for l in &want {
                let got = computed.get(l.algorithm).cloned().unwrap_or_default();
                let ok = got == l.hex;
                if !ok {
                    bad.push(format!(
                        "{} differs: {} lists {}, the file has {got}",
                        l.algorithm, l.list, l.hex
                    ));
                }
                checks.push(json!({ "list": l.list, "algorithm": l.algorithm, "listed": l.hex, "computed": got, "match": ok }));
            }
            let mut item = Item::new(ItemStatus::Acquired, rel.clone());
            item.kind = Some("file".into());
            item.stored_as = Some(CONTAINER.into());
            item.member = Some(member);
            item.size = Some(size);
            item.hashes = hasher.finish();
            item.times = Times {
                modified: Some(dfcore::host::rfc3339_utc_ns(stamps_of(&md).modified)),
                ..Times::default()
            };
            item.metadata = json!({ "provider_hashes": checks });
            if !bad.is_empty() {
                item.status = ItemStatus::Error;
                item.reason = Some(bad.join("; "));
                *tally.get_mut("mismatched").unwrap() += 1;
                ctx.count(|p| &p.errors, 1);
            } else if want.is_empty() && !lists.is_empty() {
                *tally.get_mut("unlisted").unwrap() += 1;
                if !args.allow_unlisted {
                    item.status = ItemStatus::Error;
                    item.reason = Some("not in the provider's hash lists".into());
                }
            } else if !want.is_empty() {
                *tally.get_mut("verified").unwrap() += 1;
            }
            ctx.count(|p| &p.files, 1);
            collection.add(item)?;
        }
        for (path, l) in &listed {
            if !seen.contains(path) {
                let mut item = Item::new(ItemStatus::Error, path.clone());
                item.kind = Some("file".into());
                item.reason = Some(format!(
                    "listed in {} but not in the package",
                    l.iter()
                        .map(|x| x.list.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                collection.add(item)?;
                *tally.get_mut("missing").unwrap() += 1;
            }
        }
        Ok(())
    })();
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
            "files": files.len(),
            "verified": tally["verified"],
            "mismatched": tally["mismatched"],
            "missing": tally["missing"],
            "unlisted": tally["unlisted"],
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
    fn hash_lists() {
        let gnu = "d41d8cd98f00b204e9800998ecf8427e  ./a/empty.txt\n\
                   E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 *b.bin\n# comment\n\n";
        let l = parse_list(gnu, "SHA.txt").unwrap();
        assert_eq!(l["a/empty.txt"][0].algorithm, "md5");
        assert_eq!(l["b.bin"][0].algorithm, "sha256");
        assert_eq!(
            l["b.bin"][0].hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let bsd = "SHA256 (dir\\file name.txt) = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\n";
        let l = parse_list(bsd, "x").unwrap();
        assert!(l.contains_key("dir/file name.txt"), "{l:?}");
        assert!(parse_list("nothex  file\n", "x").is_err());
        assert!(parse_list("abc  file\n", "x").is_err());
    }

    fn package(tag: &str) -> PathBuf {
        let root = PathBuf::from("/dev/shm")
            .join(format!("dfcollect_ingest_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("pkg/sub")).unwrap();
        std::fs::write(root.join("pkg/a.txt"), b"alpha").unwrap();
        std::fs::write(root.join("pkg/sub/b.bin"), vec![7u8; 2 << 20]).unwrap();
        std::fs::write(
            root.join("SHA256SUMS"),
            format!("{}  a.txt\n", crate::mail::client::sha256_hex(b"alpha")),
        )
        .unwrap();
        crate::common::test_audit_log();
        root
    }

    fn args(root: &Path, extra: &[&str]) -> IngestArgs {
        let mut argv: Vec<String> = [
            "dfcollect",
            "ingest",
            "--provider",
            "Example Mail Inc.",
            "--received-at",
            "2026-10-17T10:00:00Z",
            "--channel",
            "SFTP",
            "--allow-unlisted",
            "--allow-tmpfs",
            "-C",
            "C",
            "-E",
            "E",
            "-e",
            "x",
        ]
        .map(String::from)
        .to_vec();
        argv.push("--hashes".into());
        argv.push(root.join("SHA256SUMS").display().to_string());
        argv.push("-o".into());
        argv.push(root.join("out").display().to_string());
        argv.extend(extra.iter().map(|s| s.to_string()));
        argv.push(root.join("pkg").display().to_string());
        use clap::Parser;
        match crate::args::Cli::try_parse_from(argv).unwrap().command {
            Some(crate::args::Command::Ingest(a)) => *a,
            _ => unreachable!(),
        }
    }

    fn manifest(dir: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap()
    }

    #[test]
    fn a_tui_run_records_its_command_counts_and_can_be_stopped() {
        use crate::common::{Progress, Stop};
        use std::sync::atomic::Ordering;
        let root = package("tui");
        let a = args(&root, &[]);
        let stop: &'static Stop = Box::leak(Box::new(Stop::new()));
        let progress = Progress::default();
        let argv: Vec<String> = ["dfcollect", "ingest", "(equivalent)"]
            .map(String::from)
            .to_vec();
        let console = std::sync::Arc::new(crate::console::QuietConsole::default());
        let ctx = RunCtx {
            stop,
            progress: Some(&progress),
            console: console.clone(),
            argv: Some(argv.clone()),
            interactive: true,
            preview_at_ns: None,
            reference_entered_ns: None,
        };
        let out = run_with(&a, &ctx).unwrap();
        assert_eq!(out.code, 0, "{}", out.summary);
        let m = manifest(&root.join("out"));
        assert_eq!(m["method"]["argv"], json!(argv));
        assert_eq!(progress.files.load(Ordering::Relaxed), 2);
        assert_eq!(progress.bytes.load(Ordering::Relaxed), 5 + (2 << 20));
        assert_eq!(progress.items_total.load(Ordering::Relaxed), 2);
        assert_eq!(progress.phase(), Phase::Done);
        assert_eq!(out.summary["verified"], 1);

        // Stopped by the examiner: aborted, exit 8, the reason recorded
        let _ = std::fs::remove_dir_all(root.join("out"));
        stop.examiner.store(true, Ordering::Relaxed);
        let out = run_with(&a, &ctx).unwrap();
        assert_eq!(out.code, 8, "{}", out.summary);
        let m = manifest(&root.join("out"));
        assert_eq!(m["status"], "aborted");
        assert!(m.to_string().contains("stopped by the examiner"), "{m}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn paths_normalize() {
        assert_eq!(normalize("./x/y"), "x/y");
        assert_eq!(normalize("\\x\\y"), "x/y");
        assert_eq!(normalize(" /x "), "x");
    }
}
