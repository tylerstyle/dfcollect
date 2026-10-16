//! The ZIP64 container the acquired files go into.
//!
//! Every member carries its times twice: the DOS time of the ZIP format (two
//! seconds, no time zone; written in UTC) and, for the analysis suites, the
//! NTFS extra field (modified, accessed and created, 100 ns, UTC). A file whose
//! filesystem reports no birth time gets the Unix extended timestamp field
//! (modified, seconds) instead, so that no creation time is invented. The
//! manifest holds every time at full precision either way.

use crate::meta::Stamps;
use anyhow::{Context, Result};
use digest::Digest;
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zip::{
    write::{FullFileOptions, ZipWriter},
    CompressionMethod, DateTime, ZipArchive,
};

/// Seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01.
const FILETIME_OFFSET_SECS: i128 = 11_644_473_600;

fn filetime(ns: i128) -> u64 {
    let ticks = (ns + FILETIME_OFFSET_SECS * 1_000_000_000).div_euclid(100);
    ticks.clamp(0, i128::from(u64::MAX)) as u64
}

/// NTFS extra field (0x000a) body: reserved, tag 1, size 24, then mtime,
/// atime and creation time as FILETIME.
fn ntfs_field(modified: i128, accessed: i128, birth: i128) -> Vec<u8> {
    let mut v = Vec::with_capacity(32);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&24u16.to_le_bytes());
    for t in [modified, accessed, birth] {
        v.extend_from_slice(&filetime(t).to_le_bytes());
    }
    v
}

/// Unix extended timestamp field (0x5455) body with the modification time,
/// when it fits the field's signed 32-bit seconds.
fn extended_timestamp_field(modified: i128) -> Option<Vec<u8>> {
    let secs = i32::try_from(modified.div_euclid(1_000_000_000)).ok()?;
    let mut v = vec![0x01];
    v.extend_from_slice(&secs.to_le_bytes());
    Some(v)
}

/// The DOS date and time of a UTC timestamp; outside 1980–2107 the format's
/// earliest value (the extra fields carry the real time).
fn dos_time(ns: i128) -> DateTime {
    let text = dfcore::host::rfc3339_utc_ns(ns);
    let num = |a: usize, b: usize| text.get(a..b).and_then(|s| s.parse::<u16>().ok());
    (|| {
        DateTime::from_date_and_time(
            num(0, 4)?,
            num(5, 7)? as u8,
            num(8, 10)? as u8,
            num(11, 13)? as u8,
            num(14, 16)? as u8,
            num(17, 19)? as u8,
        )
        .ok()
    })()
    .unwrap_or_default()
}

/// The digests of one member, computed while it is copied.
pub struct Hasher {
    sha256: sha2::Sha256,
    md5: Option<md5::Md5>,
    sha1: Option<sha1::Sha1>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Hasher {
    pub fn new(md5: bool, sha1: bool) -> Self {
        Self {
            sha256: sha2::Sha256::new(),
            md5: md5.then(md5::Md5::new),
            sha1: sha1.then(sha1::Sha1::new),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.sha256.update(data);
        if let Some(h) = &mut self.md5 {
            h.update(data);
        }
        if let Some(h) = &mut self.sha1 {
            h.update(data);
        }
    }

    pub fn finish(self) -> dfcore::manifest::Hashes {
        dfcore::manifest::Hashes {
            sha256: Some(hex(&self.sha256.finalize())),
            md5: self.md5.map(|h| hex(&h.finalize())),
            sha1: self.sha1.map(|h| hex(&h.finalize())),
        }
    }
}

/// Why copying a member failed: the source could not be read, or the name is
/// taken (the item fails, the collection goes on), or the container could not
/// be written (the collection cannot go on).
#[derive(Debug)]
pub enum CopyError {
    Source(std::io::Error),
    /// Another entry already has this member name
    Duplicate(String),
    Container(anyhow::Error),
}

pub struct Container {
    zip: ZipWriter<File>,
    path: PathBuf,
    method: CompressionMethod,
    names: HashSet<String>,
}

impl Container {
    /// A new container file; refuses an existing one.
    pub fn create(path: &Path, compress: bool) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("Cannot create {}", path.display()))?;
        Ok(Self {
            zip: ZipWriter::new(file),
            path: path.to_path_buf(),
            method: if compress {
                CompressionMethod::Deflated
            } else {
                CompressionMethod::Stored
            },
            names: HashSet::new(),
        })
    }

    fn options(&self, mode: u32, stamps: &Stamps) -> Result<FullFileOptions<'static, 'static>> {
        let mut options = FullFileOptions::default()
            .compression_method(self.method)
            .large_file(true)
            .unix_permissions(mode & 0o7777)
            .last_modified_time(dos_time(stamps.modified));
        match stamps.birth {
            Some(birth) => options
                .add_extra_field(
                    0x000a,
                    ntfs_field(stamps.modified, stamps.accessed, birth),
                    false,
                )
                .context("NTFS extra field")?,
            None => {
                if let Some(field) = extended_timestamp_field(stamps.modified) {
                    options
                        .add_extra_field(0x5455, field, false)
                        .context("extended timestamp field")?;
                }
            }
        }
        Ok(options)
    }

    fn claim(&mut self, name: &str) -> std::result::Result<(), CopyError> {
        if !self.names.insert(name.to_string()) {
            return Err(CopyError::Duplicate(name.to_string()));
        }
        Ok(())
    }

    /// Copy `source` into the member `name`, hashing what is read.
    pub fn add_file(
        &mut self,
        name: &str,
        mode: u32,
        stamps: &Stamps,
        source: &mut impl Read,
        hasher: &mut Hasher,
    ) -> std::result::Result<u64, CopyError> {
        self.claim(name)?;
        let options = self.options(mode, stamps).map_err(CopyError::Container)?;
        self.zip
            .start_file(name, options)
            .with_context(|| format!("Cannot start member {name}"))
            .map_err(CopyError::Container)?;
        let mut buf = vec![0u8; 1 << 20];
        let mut total = 0u64;
        loop {
            let n = match source.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    // Take the partial member out again; its name stays claimed
                    self.zip
                        .abort_file()
                        .with_context(|| format!("Cannot remove the partial member {name}"))
                        .map_err(CopyError::Container)?;
                    return Err(CopyError::Source(e));
                }
            };
            hasher.update(&buf[..n]);
            self.zip
                .write_all(&buf[..n])
                .with_context(|| format!("Cannot write {}", self.path.display()))
                .map_err(CopyError::Container)?;
            total += n as u64;
        }
        Ok(total)
    }

    /// A directory entry (`name` ends with '/'), so its times reach the suites.
    pub fn add_directory(
        &mut self,
        name: &str,
        mode: u32,
        stamps: &Stamps,
    ) -> std::result::Result<(), CopyError> {
        self.claim(name)?;
        let options = self.options(mode, stamps).map_err(CopyError::Container)?;
        self.zip
            .add_directory(name, options)
            .with_context(|| format!("Cannot add directory {name}"))
            .map_err(CopyError::Container)
    }

    /// Write the central directory and sync the file.
    pub fn finish(self) -> Result<()> {
        let file = self
            .zip
            .finish()
            .with_context(|| format!("Cannot finish {}", self.path.display()))?;
        file.sync_all()
            .with_context(|| format!("Cannot sync {}", self.path.display()))
    }
}

/// Read every member back from the finished container and hash it.
pub fn hash_members(path: &Path) -> Result<std::collections::HashMap<String, (u64, String)>> {
    let file = File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("{} is not a readable ZIP", path.display()))?;
    let mut out = std::collections::HashMap::new();
    let mut buf = vec![0u8; 1 << 20];
    for i in 0..archive.len() {
        let mut member = archive
            .by_index(i)
            .with_context(|| format!("{}: member {i}", path.display()))?;
        if member.is_dir() {
            continue;
        }
        let name = member
            .name()
            .with_context(|| format!("{}: member {i} has no readable name", path.display()))?
            .to_string();
        let mut h = sha2::Sha256::new();
        let mut size = 0u64;
        loop {
            let n = member
                .read(&mut buf)
                .with_context(|| format!("{}: reading {name}", path.display()))?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            size += n as u64;
        }
        out.insert(name, (size, hex(&h.finalize())));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_of_known_dates() {
        assert_eq!(filetime(0), 116_444_736_000_000_000);
        assert_eq!(filetime(-FILETIME_OFFSET_SECS * 1_000_000_000), 0);
        // 100 ns resolution, rounding down
        assert_eq!(filetime(199), 116_444_736_000_000_001);
    }

    #[test]
    fn dos_time_is_utc_and_clamped() {
        let t = dos_time(dfcore::host::parse_rfc3339("2020-06-07T08:09:10Z").unwrap());
        assert_eq!((t.year(), t.month(), t.day()), (2020, 6, 7));
        assert_eq!((t.hour(), t.minute(), t.second()), (8, 9, 10));
        assert_eq!(dos_time(0), DateTime::default());
    }

    #[test]
    fn members_round_trip_with_hashes() {
        let dir = std::env::temp_dir().join(format!("dfcollect_container_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.zip");
        let stamps = Stamps {
            modified: 1_600_000_000_000_000_000,
            accessed: 1_600_000_001_000_000_000,
            changed: 1_600_000_002_000_000_000,
            birth: Some(1_500_000_000_000_000_000),
        };
        let mut c = Container::create(&path, false).unwrap();
        c.add_directory("a/", 0o755, &stamps).unwrap();
        let mut h = Hasher::new(true, true);
        let n = c
            .add_file("a/x.txt", 0o644, &stamps, &mut &b"hello"[..], &mut h)
            .unwrap();
        assert_eq!(n, 5);
        let hashes = h.finish();
        assert_eq!(
            hashes.sha256.as_deref(),
            Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
        assert_eq!(
            hashes.md5.as_deref(),
            Some("5d41402abc4b2a76b9719d911017c592")
        );
        assert!(matches!(
            c.add_file(
                "a/x.txt",
                0o644,
                &stamps,
                &mut &b"again"[..],
                &mut Hasher::new(false, false)
            ),
            Err(CopyError::Duplicate(_))
        ));
        // A source that fails after some bytes leaves no partial member
        struct Failing(usize);
        impl Read for Failing {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::other("bad sector"));
                }
                let n = self.0.min(buf.len()).min(3);
                buf[..n].fill(b'z');
                self.0 -= n;
                Ok(n)
            }
        }
        assert!(matches!(
            c.add_file(
                "a/bad.bin",
                0o644,
                &stamps,
                &mut Failing(5),
                &mut Hasher::new(false, false)
            ),
            Err(CopyError::Source(_))
        ));
        let mut h2 = Hasher::new(false, false);
        c.add_file("a/after.txt", 0o644, &stamps, &mut &b"after"[..], &mut h2)
            .unwrap();
        c.finish().unwrap();
        let members = hash_members(&path).unwrap();
        assert!(!members.contains_key("a/bad.bin"));
        assert_eq!(
            &members["a/after.txt"].1,
            h2.finish().sha256.as_ref().unwrap()
        );
        assert_eq!(members["a/x.txt"].0, 5);
        assert_eq!(&members["a/x.txt"].1, hashes.sha256.as_ref().unwrap());
        assert!(Container::create(&path, false).is_err());
    }
}
