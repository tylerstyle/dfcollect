//! dfcollect end to end. Sources and collections live in /dev/shm (tmpfs, no
//! backing disk), so every run needs --allow-writable-source --allow-tmpfs; the
//! read-only and disjointness checks on real mounts are covered by the dfnix
//! nixosTest.

use serde_json::Value;
use std::{
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Command,
};

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let root =
            PathBuf::from("/dev/shm").join(format!("dfcollect_cli_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        Self { root }
    }
    fn src(&self) -> PathBuf {
        self.root.join("src")
    }
    fn out(&self) -> PathBuf {
        self.root.join("out")
    }
    fn log(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }
    fn write(&self, rel: &str, data: &[u8]) {
        let p = self.src().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn dfcollect(s: &Scratch, args: &[&str]) -> (i32, Value, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_dfcollect"))
        .args(args)
        .env("DFNIX_AUDIT_LOG", s.log())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let json = serde_json::from_str(&stdout).unwrap_or(Value::Null);
    (
        out.status.code().unwrap_or(-1),
        json,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn files(s: &Scratch, extra: &[&str]) -> (i32, Value, String) {
    let src = s.src();
    let out = s.out();
    let mut args = vec![
        "files",
        src.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-C",
        "CASE-1",
        "-E",
        "EV-1",
        "-e",
        "tester",
        "--allow-writable-source",
        "--allow-tmpfs",
        "--json",
    ];
    args.extend_from_slice(extra);
    dfcollect(s, &args)
}

fn items(dir: &Path) -> Vec<Value> {
    std::fs::read_to_string(dir.join("items.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn set_mtime(path: &Path, rfc3339: &str) {
    let ns = dfcore::host::parse_rfc3339(rfc3339).unwrap();
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(ns as u64);
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

#[test]
fn acquires_a_tree_and_verifies_it() {
    let s = Scratch::new("tree");
    s.write("a.txt", b"alpha");
    s.write("docs/Pr\u{fc}fbericht.txt", b"beta");
    s.write("docs/empty", b"");
    s.write("deep/x/y/z.bin", &[7u8; 70_000]);
    std::os::unix::fs::symlink("a.txt", s.src().join("link")).unwrap();
    let latin1 = s.src().join(std::ffi::OsStr::from_bytes(b"caf\xe9.txt"));
    std::fs::write(&latin1, b"latin1").unwrap();
    let fifo = std::ffi::CString::new(s.src().join("pipe").as_os_str().as_bytes()).unwrap();
    // SAFETY: valid path
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);

    let (code, summary, err) = files(&s, &["--md5"]);
    assert_eq!(code, 0, "{summary} {err}");
    assert_eq!(summary["status"], "complete");
    // 5 files, 4 directories (docs, deep, deep/x, deep/x/y), 1 symlink
    assert_eq!(summary["acquired"], 10, "{summary}");
    assert_eq!(summary["skipped"], 1, "{summary}");
    assert_eq!(summary["bytes"], 5 + 4 + 70_000 + 6);

    let it = items(&s.out());
    let by_path = |p: &str| it.iter().find(|i| i["path"] == p).unwrap().clone();
    let a = by_path("a.txt");
    assert_eq!(a["member"], "a.txt");
    assert_eq!(a["stored_as"], "data.zip");
    assert_eq!(a["hashes"]["md5"], "2c1743a391305fbf367df8e4f069f9f9");
    assert!(a["times"]["modified"].as_str().unwrap().ends_with('Z'));
    assert_eq!(by_path("link")["metadata"]["target"], "a.txt");
    assert_eq!(by_path("link")["kind"], "symlink");
    assert_eq!(by_path("docs")["kind"], "directory");
    assert_eq!(by_path("pipe")["status"], "skipped");
    let latin = by_path("caf%E9.txt");
    assert_eq!(latin["size"], 6);

    let out = s.out();
    let (code, report, _) = dfcollect(&s, &["verify", out.to_str().unwrap(), "--json"]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["members_ok"], 5);
    assert_eq!(report["audit_finish_found"], true);

    // Change one byte of a stored member: verify must fail
    let zip_path = out.join("data.zip");
    let mut bytes = std::fs::read(&zip_path).unwrap();
    let pos = bytes.windows(5).position(|w| w == b"alpha").unwrap();
    bytes[pos] = b'A';
    std::fs::write(&zip_path, bytes).unwrap();
    let (code, report, _) = dfcollect(&s, &["verify", out.to_str().unwrap(), "--json"]);
    assert_eq!(code, 5, "{report}");
}

#[test]
fn the_scope_decides_before_reading_and_names_stay_out() {
    let s = Scratch::new("scope");
    s.write("docs/report.txt", b"in");
    s.write("docs/private/diary.txt", b"out");
    s.write("other/notes.txt", b"out");
    let (code, summary, err) = files(
        &s,
        &[
            "--include",
            "docs/**",
            "--exclude",
            "docs/private/**",
            "--legal-basis",
            "AG Musterstadt 12 Gs 34/26",
        ],
    );
    assert_eq!(code, 0, "{summary} {err}");
    assert_eq!(summary["excluded_trees"], 1);
    let it = items(&s.out());
    let paths: Vec<&str> = it.iter().map(|i| i["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["docs/report.txt"], "{it:?}");
    // Nothing about out-of-scope files but counts by reason
    let all = std::fs::read_to_string(s.out().join("items.jsonl")).unwrap()
        + &std::fs::read_to_string(s.out().join("manifest.json")).unwrap();
    assert!(
        !all.contains("diary") && !all.contains("notes.txt"),
        "{all}"
    );
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(s.out().join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(
        manifest["scope"]["legal_basis"],
        "AG Musterstadt 12 Gs 34/26"
    );
    let unlisted = &manifest["totals"]["unlisted_out_of_scope"];
    assert_eq!(unlisted["matches no include pattern"], 1, "{unlisted}");
    assert_eq!(
        unlisted["directory tree excluded by docs/private/**"], 1,
        "{unlisted}"
    );
}

#[test]
fn the_time_window_applies_to_the_chosen_time() {
    let s = Scratch::new("window");
    s.write("old.txt", b"old");
    s.write("new.txt", b"new");
    set_mtime(&s.src().join("old.txt"), "2025-06-01T00:00:00Z");
    set_mtime(&s.src().join("new.txt"), "2026-03-01T12:00:00Z");
    let (code, summary, err) = files(
        &s,
        &[
            "--not-before",
            "2026-01-01T00:00:00+01:00",
            "--not-after",
            "2026-07-01T00:00:00Z",
            "--list-out-of-scope",
        ],
    );
    assert_eq!(code, 0, "{summary} {err}");
    let it = items(&s.out());
    let status = |p: &str| it.iter().find(|i| i["path"] == p).unwrap()["status"].clone();
    assert_eq!(status("new.txt"), "acquired");
    assert_eq!(status("old.txt"), "out_of_scope");
    let old = it.iter().find(|i| i["path"] == "old.txt").unwrap();
    assert_eq!(old["reason"], "mtime before the time window");
    assert!(old.get("hashes").and_then(|h| h.get("sha256")).is_none());
}

#[test]
fn refuses_unsafe_destinations_and_bad_arguments() {
    let s = Scratch::new("refuse");
    s.write("a.txt", b"a");

    // Collection directory inside the source
    let inside = s.src().join("out");
    let (code, _, err) = dfcollect(
        &s,
        &[
            "files",
            s.src().to_str().unwrap(),
            "-o",
            inside.to_str().unwrap(),
            "-C",
            "C",
            "-E",
            "E",
            "-e",
            "x",
            "--allow-writable-source",
            "--allow-tmpfs",
        ],
    );
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("inside the source"), "{err}");

    // A read-write source without the flag
    let out = s.out();
    let (code, _, err) = dfcollect(
        &s,
        &[
            "files",
            s.src().to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-C",
            "C",
            "-E",
            "E",
            "-e",
            "x",
            "--allow-tmpfs",
        ],
    );
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("read-write mount"), "{err}");

    // RAM-backed destination without the flag
    let (code, _, err) = dfcollect(
        &s,
        &[
            "files",
            s.src().to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-C",
            "C",
            "-E",
            "E",
            "-e",
            "x",
            "--allow-writable-source",
        ],
    );
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("tmpfs"), "{err}");

    // A non-empty collection directory
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("x"), b"x").unwrap();
    let (code, _, err) = files(&s, &[]);
    assert_eq!(code, 3, "{err}");
    std::fs::remove_dir_all(&out).unwrap();

    // Usage errors: a scope file with a typo, a scope file plus scope flags,
    // a bad time
    let scope = s.root.join("scope.json");
    std::fs::write(&scope, r#"{"includes": ["a.txt"]}"#).unwrap();
    let (code, _, err) = files(&s, &["--scope", scope.to_str().unwrap()]);
    assert_eq!(code, 2, "{err}");
    std::fs::write(&scope, r#"{"include": ["a.txt"]}"#).unwrap();
    let (code, _, _) = files(&s, &["--scope", scope.to_str().unwrap(), "--include", "x"]);
    assert_eq!(code, 2);
    let (code, _, err) = files(&s, &["--not-before", "yesterday"]);
    assert_eq!(code, 2, "{err}");
    // Nothing was created by any refused run
    assert!(!out.exists());
}

#[test]
fn a_container_name_collision_fails_one_item_not_the_collection() {
    let s = Scratch::new("collide");
    std::fs::write(
        s.src().join(std::ffi::OsStr::from_bytes(b"caf\xe9.txt")),
        b"latin1",
    )
    .unwrap();
    s.write("caf%E9.txt", b"literal");
    s.write("z.txt", b"after");
    let (code, summary, err) = files(&s, &[]);
    assert_eq!(code, 7, "{summary} {err}");
    assert_eq!(summary["acquired"], 2, "{summary}");
    assert_eq!(summary["errors"], 1, "{summary}");
    let it = items(&s.out());
    let failed: Vec<_> = it.iter().filter(|i| i["status"] == "error").collect();
    assert!(failed[0]["reason"]
        .as_str()
        .unwrap()
        .contains("already has the container name"));
    let out = s.out();
    let (code, _, _) = dfcollect(&s, &["verify", out.to_str().unwrap()]);
    assert_eq!(code, 0);
}
