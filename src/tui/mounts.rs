//! Mount discovery from `/proc/self/mountinfo` for the source picker and the
//! default target collection path, plus path-component sanitisation.

use crate::common;
use dfcore::{
    lsblk::{is_evidence_mount, is_mount_system},
    sysfs::{self, MountEntry},
};
use std::path::{Path, PathBuf};

/// System and virtual trees never shown in the source mount picker.
const HIDDEN_PREFIXES: &[&str] = &["/proc", "/sys", "/dev", "/etc", "/var", "/tmp", "/usr"];

/// A mount offered in the source picker or used as a writable target mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountChoice {
    pub mount_point: PathBuf,
    pub source: String,
    pub read_only: bool,
    pub free_bytes: Option<u64>,
}

/// Whether `path` belongs to the running system or a virtual tree that should
/// never be offered as an acquisition source.
pub fn is_hidden_mount(path: &Path) -> bool {
    let s = path.to_string_lossy();
    if is_mount_system(&s) {
        return true;
    }
    HIDDEN_PREFIXES
        .iter()
        .any(|p| s == *p || s.starts_with(&format!("{p}/")))
}

/// Filter and order parsed mount entries using a caller-supplied stat function
/// `(read_only, free_bytes)`.
pub fn classify_mounts(
    entries: &[MountEntry],
    mut inspect: impl FnMut(&Path) -> Option<(bool, Option<u64>)>,
) -> (Vec<MountChoice>, Vec<MountChoice>) {
    let mut sources = Vec::new();
    let mut targets = Vec::new();

    for e in entries {
        if is_hidden_mount(&e.mount_point) {
            continue;
        }
        let Some((read_only, free_bytes)) = inspect(&e.mount_point) else {
            continue;
        };
        let choice = MountChoice {
            mount_point: e.mount_point.clone(),
            source: e.source.clone(),
            read_only,
            free_bytes,
        };
        if read_only {
            if let Some(pos) = sources
                .iter()
                .position(|c: &MountChoice| c.mount_point == choice.mount_point)
            {
                sources[pos] = choice;
            } else {
                sources.push(choice);
            }
        } else if e.mount_point.starts_with("/media/target")
            && e.mount_point != Path::new("/media/target")
        {
            if let Some(pos) = targets
                .iter()
                .position(|c: &MountChoice| c.mount_point == choice.mount_point)
            {
                targets[pos] = choice;
            } else {
                targets.push(choice);
            }
        }
    }

    // /media/evidence/* first, then other read-only mounts (e.g. dfnet shares)
    sources.sort_by(|a, b| {
        let a_ev = is_evidence_mount(&a.mount_point.to_string_lossy());
        let b_ev = is_evidence_mount(&b.mount_point.to_string_lossy());
        b_ev.cmp(&a_ev)
            .then_with(|| a.mount_point.cmp(&b.mount_point))
    });
    targets.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));
    (sources, targets)
}

/// Read `/proc/self/mountinfo` on this host and return `(read_only_sources, writable_targets)`.
pub fn discover_mounts() -> (Vec<MountChoice>, Vec<MountChoice>) {
    let content = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let entries = sysfs::parse_mountinfo(&content);
    classify_mounts(&entries, |p| {
        let info = common::fs_info(p).ok()?;
        let free = common::free_bytes(p);
        Some((info.read_only, free))
    })
}

/// Sanitise a case or evidence string into a safe single path component:
/// characters outside `[A-Za-z0-9._-]` become `_`, consecutive `_` are
/// collapsed, leading/trailing `.` and `_` are trimmed, and `fallback` is used
/// when the result would be empty.
pub fn sanitize_component(raw: &str, fallback: &str) -> String {
    let mut out = String::new();
    let mut last_underscore = false;
    for c in raw.trim().chars() {
        let allowed = c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
        if allowed && c != '_' {
            out.push(c);
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    let trimmed = out.trim_matches(|c| c == '.' || c == '_');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Default collection directory `/media/target/<writable mount>/<case>/<evidence>`
/// once `case` and `evidence` are non-empty and a writable target mount exists.
pub fn suggest_output_dir(target_mount: &Path, case: &str, evidence: &str) -> Option<PathBuf> {
    if case.trim().is_empty() || evidence.trim().is_empty() {
        return None;
    }
    let c = sanitize_component(case, "case");
    let e = sanitize_component(evidence, "evidence");
    Some(target_mount.join(c).join(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitises_case_and_evidence_components() {
        assert_eq!(sanitize_component("VG 12345/26", "case"), "VG_12345_26");
        assert_eq!(sanitize_component("  share01  ", "ev"), "share01");
        assert_eq!(sanitize_component("../etc/passwd", "ev"), "etc_passwd");
        assert_eq!(sanitize_component("...", "ev"), "ev");
        assert_eq!(sanitize_component("   ", "ev"), "ev");
        assert_eq!(sanitize_component("A::B / C\\D", "case"), "A_B_C_D");
        assert_eq!(
            suggest_output_dir(Path::new("/media/target/sdc1"), "VG 12345/26", "share 01"),
            Some(PathBuf::from("/media/target/sdc1/VG_12345_26/share_01"))
        );
        assert_eq!(
            suggest_output_dir(Path::new("/media/target/sdc1"), "", "share01"),
            None
        );
    }

    #[test]
    fn hides_system_and_virtual_mounts_and_separates_ro_from_rw_targets() {
        let mountinfo = "\
22 1 0:20 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n\
23 1 0:21 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro\n\
24 23 0:22 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 ro\n\
25 1 0:6 / /dev rw,nosuid - devtmpfs devtmpfs rw\n\
26 1 259:2 / / rw,relatime - ext4 /dev/nvme0n1p2 rw\n\
27 1 259:2 /nix/store /nix/store ro,relatime - ext4 /dev/nvme0n1p2 ro\n\
28 1 0:50 / /media/target/smb_nas ro,relatime - cifs //files.example.org/share ro\n\
29 1 8:17 / /media/evidence/sdb1 ro,relatime - ntfs3 /dev/sdb1 ro\n\
30 1 8:33 / /media/target/sdc1 rw,relatime - exfat /dev/sdc1 rw\n";
        let entries = sysfs::parse_mountinfo(mountinfo);
        let (sources, targets) = classify_mounts(&entries, |p| {
            let s = p.to_string_lossy();
            let ro = s.contains("sdb1")
                || s.contains("smb_nas")
                || s.starts_with("/sys")
                || s.starts_with("/nix");
            Some((ro, Some(100 << 30)))
        });
        let src_paths: Vec<&Path> = sources.iter().map(|m| m.mount_point.as_path()).collect();
        // /media/evidence/sdb1 comes before /media/target/smb_nas; /sys and /nix are hidden
        assert_eq!(
            src_paths,
            [
                Path::new("/media/evidence/sdb1"),
                Path::new("/media/target/smb_nas"),
            ]
        );
        // Only writable mounts under /media/target qualify as output targets
        let tgt_paths: Vec<&Path> = targets.iter().map(|m| m.mount_point.as_path()).collect();
        assert_eq!(tgt_paths, [Path::new("/media/target/sdc1")]);
    }
}
