//! What a source entry is and its times, owner, mode and extended attributes,
//! read without following symlinks.

use dfcore::{host, manifest::Times};
use serde_json::{json, Map, Value};
use std::{
    ffi::{CString, OsStr},
    fs::Metadata,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
    },
    path::Path,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
    Special(&'static str),
}

impl Kind {
    pub fn of(md: &Metadata) -> Kind {
        let ft = md.file_type();
        if ft.is_file() {
            Kind::File
        } else if ft.is_dir() {
            Kind::Directory
        } else if ft.is_symlink() {
            Kind::Symlink
        } else if ft.is_fifo() {
            Kind::Special("fifo")
        } else if ft.is_socket() {
            Kind::Special("socket")
        } else if ft.is_block_device() {
            Kind::Special("block device")
        } else if ft.is_char_device() {
            Kind::Special("character device")
        } else {
            Kind::Special("unknown type")
        }
    }

    /// `Item.kind`: absent for a file
    pub fn item_kind(self) -> Option<String> {
        match self {
            Kind::File => None,
            Kind::Directory => Some("directory".into()),
            Kind::Symlink => Some("symlink".into()),
            Kind::Special(_) => Some("special".into()),
        }
    }
}

/// Times in nanoseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamps {
    pub modified: i128,
    pub accessed: i128,
    pub changed: i128,
    /// Not every filesystem (and not every kernel) reports a birth time
    pub birth: Option<i128>,
}

impl Stamps {
    pub fn of(md: &Metadata) -> Stamps {
        let ns = |secs: i64, nsec: i64| i128::from(secs) * 1_000_000_000 + i128::from(nsec);
        Stamps {
            modified: ns(md.mtime(), md.mtime_nsec()),
            accessed: ns(md.atime(), md.atime_nsec()),
            changed: ns(md.ctime(), md.ctime_nsec()),
            // std reads the birth time with statx where the filesystem has one
            birth: md.created().ok().map(host::system_time_ns),
        }
    }

    pub fn times(&self) -> Times {
        Times {
            modified: Some(host::rfc3339_utc_ns(self.modified)),
            accessed: Some(host::rfc3339_utc_ns(self.accessed)),
            changed: Some(host::rfc3339_utc_ns(self.changed)),
            birth: self.birth.map(host::rfc3339_utc_ns),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Extended attributes (including POSIX ACLs, `system.posix_acl_*`), values
/// as hex. Errors become a `"error"` entry instead of failing the item.
pub fn xattrs(path: &Path) -> Value {
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return Value::Null;
    };
    let mut attrs = Map::new();
    // SAFETY: a null buffer of size 0 asks for the needed size
    let size = unsafe { libc::llistxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENOTSUP) => Value::Null,
            _ => json!({ "error": err.to_string() }),
        };
    }
    if size == 0 {
        return Value::Null;
    }
    let mut names = vec![0u8; size as usize];
    // SAFETY: the buffer holds `names.len()` bytes
    let size = unsafe { libc::llistxattr(c_path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if size < 0 {
        return json!({ "error": std::io::Error::last_os_error().to_string() });
    }
    names.truncate(size as usize);
    for name in names.split(|&b| b == 0).filter(|n| !n.is_empty()) {
        let Ok(c_name) = CString::new(name) else {
            continue;
        };
        let key = String::from_utf8_lossy(name).into_owned();
        // SAFETY: size query as above
        let len =
            unsafe { libc::lgetxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        if len < 0 {
            attrs.insert(
                key,
                json!({ "error": std::io::Error::last_os_error().to_string() }),
            );
            continue;
        }
        let mut value = vec![0u8; len as usize];
        // SAFETY: the buffer holds `value.len()` bytes
        let len = unsafe {
            libc::lgetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if len < 0 {
            attrs.insert(
                key,
                json!({ "error": std::io::Error::last_os_error().to_string() }),
            );
            continue;
        }
        value.truncate(len as usize);
        attrs.insert(key, Value::String(hex(&value)));
    }
    Value::Object(attrs)
}

/// Owner, mode, inode and link count, plus extended attributes and the link
/// target of a symlink.
pub fn metadata(path: &Path, md: &Metadata, kind: Kind) -> Value {
    let mut m = Map::new();
    m.insert("mode".into(), json!(format!("{:06o}", md.mode())));
    m.insert("uid".into(), json!(md.uid()));
    m.insert("gid".into(), json!(md.gid()));
    m.insert("inode".into(), json!(md.ino()));
    m.insert("links".into(), json!(md.nlink()));
    if let Kind::Special(what) = kind {
        m.insert("type".into(), json!(what));
        if matches!(what, "block device" | "character device") {
            m.insert(
                "rdev".into(),
                json!(format!(
                    "{}:{}",
                    libc::major(md.rdev() as libc::dev_t),
                    libc::minor(md.rdev() as libc::dev_t)
                )),
            );
        }
    }
    if kind == Kind::Symlink {
        match std::fs::read_link(path) {
            Ok(target) => {
                m.insert("target".into(), json!(display_bytes(target.as_os_str())));
                if std::str::from_utf8(target.as_os_str().as_bytes()).is_err() {
                    m.insert(
                        "target_bytes".into(),
                        json!(hex(target.as_os_str().as_bytes())),
                    );
                }
            }
            Err(e) => {
                m.insert("target_error".into(), json!(e.to_string()));
            }
        }
    }
    let x = xattrs(path);
    if !x.is_null() {
        m.insert("xattrs".into(), x);
    }
    Value::Object(m)
}

/// A name for display and as a ZIP member: valid UTF-8 as is, any other byte
/// as `%XX` (and `%` itself as `%25` only in names that needed escaping).
pub fn display_bytes(s: &OsStr) -> String {
    let bytes = s.as_bytes();
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    let mut out = String::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                out.push_str(&text.replace('%', "%25"));
                break;
            }
            Err(e) => {
                let (valid, after) = rest.split_at(e.valid_up_to());
                out.push_str(
                    &std::str::from_utf8(valid)
                        .expect("checked")
                        .replace('%', "%25"),
                );
                let bad = e.error_len().unwrap_or(after.len());
                for b in &after[..bad] {
                    out.push_str(&format!("%{b:02X}"));
                }
                rest = &after[bad..];
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn names_that_are_not_utf8_are_escaped() {
        assert_eq!(
            display_bytes(OsStr::new("Pr\u{fc}fbericht.txt")),
            "Pr\u{fc}fbericht.txt"
        );
        assert_eq!(display_bytes(OsStr::new("50%.txt")), "50%.txt");
        let latin1 = OsStr::from_bytes(b"Pr\xfcf 50%.txt");
        assert_eq!(display_bytes(latin1), "Pr%FCf 50%25.txt");
    }

    #[test]
    fn stamps_of_a_file() {
        let path = std::env::temp_dir().join(format!("dfcollect_meta_{}", std::process::id()));
        std::fs::write(&path, b"x").unwrap();
        let md = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(Kind::of(&md), Kind::File);
        let s = Stamps::of(&md);
        assert!(s.modified > 0 && s.changed > 0);
        let t = s.times();
        assert!(t.modified.unwrap().ends_with('Z'));
        let m = metadata(&path, &md, Kind::File);
        assert!(m["mode"].as_str().unwrap().starts_with("100"));
        std::fs::remove_file(&path).unwrap();
    }
}
