//! `dfcollect verify`: the records, the container members and the audit
//! anchors of a finished collection.

use crate::{container, files::CONTAINER, Usage};
use anyhow::Result;
use dfcore::manifest::{self, ItemStatus};
use serde_json::{json, Value};
use std::path::Path;

pub struct Outcome {
    pub code: u8,
    pub summary: Value,
}

pub fn run(dir: &Path) -> Result<Outcome> {
    if !dir.join(manifest::MANIFEST).is_file() {
        return Err(Usage(format!(
            "{} holds no collection (no {})",
            dir.display(),
            manifest::MANIFEST
        ))
        .into());
    }
    let report = manifest::verify(dir)?;
    let mut members_ok = 0u64;
    let mut member_problems = Vec::new();
    let container_path = dir.join(CONTAINER);
    let members = if container_path.exists() {
        Some(container::hash_members(&container_path))
    } else {
        None
    };
    match members {
        Some(Err(e)) => member_problems.push(format!("{CONTAINER}: {e:#}")),
        Some(Ok(members)) => {
            manifest::for_each_item(dir, |item| {
                if let (ItemStatus::Acquired, Some(member)) = (item.status, &item.member) {
                    let want = (
                        item.size.unwrap_or(0),
                        item.hashes.sha256.clone().unwrap_or_default(),
                    );
                    match members.get(member) {
                        Some(got) if *got == want => members_ok += 1,
                        Some(_) => {
                            member_problems.push(format!("{member}: size or SHA-256 differs"))
                        }
                        None => member_problems.push(format!("{member}: missing from {CONTAINER}")),
                    }
                }
                Ok(())
            })?;
        }
        None => {}
    }
    let ok = report.ok() && member_problems.is_empty();
    let code = if ok {
        0
    } else if !member_problems.is_empty()
        || !report.items_mismatch.is_empty()
        || !report.items_missing.is_empty()
        || !report.problems.is_empty()
    {
        5
    } else {
        // Only the audit anchors could not be found
        4
    };
    Ok(Outcome {
        code,
        summary: json!({
            "collection": dir,
            "ok": ok,
            "status": report.status,
            "members_ok": members_ok,
            "member_problems": member_problems,
            "files_ok": report.items_ok,
            "files_mismatch": report.items_mismatch,
            "files_missing": report.items_missing,
            "audit_anchor_found": report.audit_anchor_found,
            "audit_finish_found": report.audit_finish_found,
            "problems": report.problems,
        }),
    })
}
