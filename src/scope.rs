//! The scope of a run, from a scope file or from the command line.

use crate::{
    args::{ScopeArgs, UnknownTimeArg},
    Usage,
};
use anyhow::Result;
use dfcore::manifest::{Scope, UnknownTime};

pub fn build(args: &ScopeArgs) -> Result<Scope> {
    let flags_given = args.legal_basis.is_some()
        || !args.include.is_empty()
        || !args.exclude.is_empty()
        || args.not_before.is_some()
        || args.not_after.is_some();
    if let Some(path) = &args.scope {
        if flags_given {
            return Err(Usage(
                "--scope excludes --legal-basis, --include, --exclude, --not-before and --not-after"
                    .into(),
            )
            .into());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| Usage(format!("scope file {}: {e}", path.display())))?;
        let scope: Scope = serde_json::from_str(&text)
            .map_err(|e| Usage(format!("scope file {}: {e}", path.display())))?;
        return Ok(scope);
    }
    let window = args.not_before.is_some() || args.not_after.is_some();
    Ok(Scope {
        legal_basis: args.legal_basis.clone(),
        accounts: Vec::new(),
        include: args.include.clone(),
        exclude: args.exclude.clone(),
        not_before: args.not_before.clone(),
        not_after: args.not_after.clone(),
        time_basis: window.then(|| args.time_basis.name().to_string()),
        unknown_time: match args.unknown_time {
            UnknownTimeArg::Exclude => UnknownTime::Exclude,
            UnknownTimeArg::Include => UnknownTime::Include,
        },
        notes: None,
    })
}
