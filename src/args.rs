//! Command line.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "dfcollect",
    version,
    about = "Logical forensic acquisition with scope, per-item hashes, manifest and audit records",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Acquire files from a directory on a read-only mount (dfmount evidence
    /// mounts, dfnet SMB/NFS shares) into a ZIP64 container with a manifest
    Files(Box<FilesArgs>),
    /// Acquire a mailbox over IMAP, read-only by protocol (EXAMINE, BODY.PEEK[])
    Imap(Box<ImapArgs>),
    /// Acquire a Microsoft 365 mailbox through Microsoft Graph (GET only)
    Graph(Box<GraphArgs>),
    /// Re-check a collection: records, container members and audit anchors
    Verify(VerifyArgs),
}

/// Case and chain-of-custody fields. Case, evidence and examiner are required.
#[derive(Args, Debug, Clone)]
pub struct CaseArgs {
    /// Case number (required), e.g. "VG 12345/26"
    #[arg(
        long,
        short = 'C',
        value_name = "CASE",
        help_heading = "Case (chain of custody)"
    )]
    pub case: String,

    /// Evidence (exhibit) number (required), e.g. share01
    #[arg(
        long,
        short = 'E',
        value_name = "EVIDENCE",
        help_heading = "Case (chain of custody)"
    )]
    pub evidence: String,

    /// Examiner name or ID (required)
    #[arg(
        long,
        short = 'e',
        value_name = "EXAMINER",
        help_heading = "Case (chain of custody)"
    )]
    pub examiner: String,

    /// What is being acquired
    #[arg(long, value_name = "TEXT", help_heading = "Case (chain of custody)")]
    pub description: Option<String>,

    #[arg(long, value_name = "TEXT", help_heading = "Case (chain of custody)")]
    pub notes: Option<String>,
}

/// Which time of a file the scope's time window applies to.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeBasis {
    Modified,
    Accessed,
    Changed,
    Birth,
}

impl TimeBasis {
    pub fn name(self) -> &'static str {
        match self {
            TimeBasis::Modified => "mtime",
            TimeBasis::Accessed => "atime",
            TimeBasis::Changed => "ctime",
            TimeBasis::Birth => "birth time",
        }
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownTimeArg {
    Exclude,
    Include,
}

/// The scope: given as a JSON file (`--scope`) or with the options below.
#[derive(Args, Debug, Clone)]
pub struct ScopeArgs {
    /// Scope file (JSON, dfcore ScopeSpec); excludes the other scope options
    #[arg(long, value_name = "FILE", help_heading = "Scope")]
    pub scope: Option<PathBuf>,

    /// Order or legal basis, e.g. "AG Musterstadt 12 Gs 34/26 of 2026-10-01"
    #[arg(long, value_name = "TEXT", help_heading = "Scope")]
    pub legal_basis: Option<String>,

    /// Path pattern to acquire (repeatable; relative to the source directory;
    /// `*` and `?` within a segment, `**` across segments). Default: everything
    #[arg(long, value_name = "PATTERN", help_heading = "Scope")]
    pub include: Vec<String>,

    /// Path pattern to leave out even when included (repeatable)
    #[arg(long, value_name = "PATTERN", help_heading = "Scope")]
    pub exclude: Vec<String>,

    /// Time window start, inclusive (RFC 3339, e.g. 2026-01-01T00:00:00+01:00)
    #[arg(long, value_name = "TIME", help_heading = "Scope")]
    pub not_before: Option<String>,

    /// Time window end, exclusive (RFC 3339)
    #[arg(long, value_name = "TIME", help_heading = "Scope")]
    pub not_after: Option<String>,

    /// File time the window applies to
    #[arg(long, value_enum, default_value = "modified", help_heading = "Scope")]
    pub time_basis: TimeBasis,

    /// Files whose time is unknown when a window is set
    #[arg(long, value_enum, default_value = "exclude", help_heading = "Scope")]
    pub unknown_time: UnknownTimeArg,

    /// List every file the scope leaves out by name in items.jsonl. By default
    /// they are only counted by reason, so no names outside the scope are recorded
    #[arg(long, help_heading = "Scope")]
    pub list_out_of_scope: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ClockArgs {
    /// Reference time read off a trusted clock when starting (RFC 3339)
    #[arg(
        long,
        value_name = "TIME",
        requires = "reference_how",
        help_heading = "Time"
    )]
    pub reference_time: Option<String>,

    /// Where the reference time comes from (radio clock, phone, ...)
    #[arg(
        long,
        value_name = "TEXT",
        requires = "reference_time",
        help_heading = "Time"
    )]
    pub reference_how: Option<String>,
}

#[derive(Args, Debug)]
pub struct FilesArgs {
    /// Directory to acquire, on a read-only mount
    #[arg(value_name = "SOURCE")]
    pub source: PathBuf,

    /// New collection directory (on a target drive, not on the source)
    #[arg(long, short = 'o', value_name = "DIR")]
    pub output: PathBuf,

    #[command(flatten)]
    pub case: CaseArgs,

    #[command(flatten)]
    pub scope: ScopeArgs,

    #[command(flatten)]
    pub clock: ClockArgs,

    /// Also compute MD5 for every file
    #[arg(long, help_heading = "Hashes")]
    pub md5: bool,

    /// Also compute SHA-1 for every file
    #[arg(long, help_heading = "Hashes")]
    pub sha1: bool,

    /// Deflate the container members (slower; default: stored uncompressed)
    #[arg(long, help_heading = "Output")]
    pub compress: bool,

    /// Accept a collection directory on a RAM-backed filesystem (tmpfs)
    #[arg(long, help_heading = "Safety")]
    pub allow_tmpfs: bool,

    /// Acquire from a mount that is not read-only (recorded in the manifest)
    #[arg(long, help_heading = "Safety")]
    pub allow_writable_source: bool,

    /// Print the result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ImapArgs {
    /// IMAP server: host, host:port or [IPv6]:port
    #[arg(value_name = "SERVER")]
    pub server: String,

    /// Account to log in as
    #[arg(long, short = 'u', value_name = "USER", help_heading = "Account")]
    pub user: String,

    /// File whose first line is the password (default: asked on the terminal)
    #[arg(long, value_name = "FILE", help_heading = "Account")]
    pub password_file: Option<PathBuf>,

    /// File whose first line is an OAuth 2.0 access token (XOAUTH2)
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with = "password_file",
        help_heading = "Account"
    )]
    pub token_file: Option<PathBuf>,

    #[arg(long, value_enum, default_value = "auto", help_heading = "Account")]
    pub auth: crate::mail::Auth,

    /// Transport: TLS from the start (993), STARTTLS (143) or plaintext (tests only)
    #[arg(long, value_enum, default_value = "tls", help_heading = "Connection")]
    pub security: crate::mail::Security,

    /// Accept exactly the server certificate with this SHA-256 (hex) instead of
    /// checking it against the system's CAs (internal CAs, self-signed servers)
    #[arg(long, value_name = "SHA256", help_heading = "Connection")]
    pub tls_sha256: Option<String>,

    /// Network timeout in seconds
    #[arg(long, default_value = "120", help_heading = "Connection")]
    pub timeout: u64,

    /// New collection directory (on a target drive)
    #[arg(long, short = 'o', value_name = "DIR")]
    pub output: PathBuf,

    #[command(flatten)]
    pub case: CaseArgs,

    /// Scope: --include/--exclude match `<folder>/<uid>` (folders with `/`
    /// between levels, e.g. `INBOX/**`); the time window applies to INTERNALDATE
    #[command(flatten)]
    pub scope: ScopeArgs,

    #[command(flatten)]
    pub clock: ClockArgs,

    /// Also compute MD5 for every message
    #[arg(long, help_heading = "Hashes")]
    pub md5: bool,

    /// Also compute SHA-1 for every message
    #[arg(long, help_heading = "Hashes")]
    pub sha1: bool,

    /// Deflate the container members
    #[arg(long, help_heading = "Output")]
    pub compress: bool,

    /// Accept a collection directory on a RAM-backed filesystem (tmpfs)
    #[arg(long, help_heading = "Safety")]
    pub allow_tmpfs: bool,

    /// Print the result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct GraphArgs {
    /// Mailbox: `me` (the account signed in with --auth device) or a user's
    /// address, UPN or id
    #[arg(
        long,
        default_value = "me",
        value_name = "MAILBOX",
        help_heading = "Account"
    )]
    pub mailbox: String,

    /// device: sign in as the account (device code, delegated Mail.Read);
    /// app: application permission Mail.Read, with the tenant's cooperation;
    /// token: an access token from --token-file
    #[arg(long, value_enum, default_value = "device", help_heading = "Account")]
    pub auth: crate::graph::GraphAuth,

    /// Tenant id or domain (`organizations`: any work or school account)
    #[arg(long, default_value = "organizations", help_heading = "Account")]
    pub tenant: String,

    /// Application (client) id of your app registration (public client flows
    /// allowed for --auth device)
    #[arg(long, value_name = "ID", help_heading = "Account")]
    pub client_id: Option<String>,

    /// File whose first line is the client secret (--auth app; default: asked
    /// on the terminal)
    #[arg(long, value_name = "FILE", help_heading = "Account")]
    pub client_secret_file: Option<PathBuf>,

    /// File whose first line is an access token for Graph (--auth token)
    #[arg(long, value_name = "FILE", help_heading = "Account")]
    pub token_file: Option<PathBuf>,

    /// Graph endpoint (national clouds: https://graph.microsoft.us,
    /// https://dod-graph.microsoft.us, https://microsoftgraph.chinacloudapi.cn)
    #[arg(
        long,
        default_value = "https://graph.microsoft.com",
        value_name = "URL",
        help_heading = "Connection"
    )]
    pub graph_endpoint: String,

    /// Identity platform (national clouds: https://login.microsoftonline.us,
    /// https://login.chinacloudapi.cn)
    #[arg(
        long,
        default_value = "https://login.microsoftonline.com",
        value_name = "URL",
        help_heading = "Connection"
    )]
    pub login_endpoint: String,

    /// Network timeout in seconds
    #[arg(long, default_value = "120", help_heading = "Connection")]
    pub timeout: u64,

    /// New collection directory (on a target drive)
    #[arg(long, short = 'o', value_name = "DIR")]
    pub output: PathBuf,

    #[command(flatten)]
    pub case: CaseArgs,

    /// Scope: --include/--exclude match `<folder>/<received>Z-<id hash>`
    /// (folders with `/` between levels, e.g. `Inbox/**`); the time window
    /// applies to receivedDateTime
    #[command(flatten)]
    pub scope: ScopeArgs,

    #[command(flatten)]
    pub clock: ClockArgs,

    /// Also compute MD5 for every message
    #[arg(long, help_heading = "Hashes")]
    pub md5: bool,

    /// Also compute SHA-1 for every message
    #[arg(long, help_heading = "Hashes")]
    pub sha1: bool,

    /// Deflate the container members
    #[arg(long, help_heading = "Output")]
    pub compress: bool,

    /// Accept a collection directory on a RAM-backed filesystem (tmpfs)
    #[arg(long, help_heading = "Safety")]
    pub allow_tmpfs: bool,

    /// Print the result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Collection directory
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,

    /// Print the result as JSON
    #[arg(long)]
    pub json: bool,
}
