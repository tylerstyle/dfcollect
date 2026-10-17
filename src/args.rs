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
    /// Without a command, dfcollect opens its terminal UI
    #[command(subcommand)]
    pub command: Option<Command>,
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
    /// Acquire a Google Workspace or Gmail mailbox through the Gmail API (GET only, format=raw)
    Gmail(Box<GmailArgs>),
    /// Acquire files from a cloud or remote service through rclone (lsjson
    /// and cat only), checked against the provider's own hashes
    Cloud(Box<CloudArgs>),
    /// Dump PostgreSQL or MariaDB/MySQL databases with their own tools,
    /// consistently, with the server's clock and settings recorded
    Db(Box<DbArgs>),
    /// Acquire a Microsoft 365 tenant's sign-in logs, directory audits and
    /// Unified Audit Log for a time window through Microsoft Graph
    #[command(name = "m365-logs")]
    M365Logs(Box<M365LogsArgs>),
    /// Take a provider's delivered data package (e-Evidence production orders,
    /// provider exports) into a collection, checked against the provider's hashes
    Ingest(Box<IngestArgs>),
    /// Re-check a collection: records, container members and audit anchors
    Verify(VerifyArgs),
}

/// Case and chain-of-custody fields. Case, evidence and examiner are required.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
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
#[derive(Args, Debug, Clone, PartialEq, Eq)]
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

#[derive(Args, Debug, Clone, PartialEq, Eq)]
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

#[derive(Args, Debug, Clone, PartialEq, Eq)]
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

    /// Run the checks and walk the source with the scope's decisions, then
    /// print what would be acquired. Reads only directory listings and file
    /// metadata, opens no file and writes nothing
    #[arg(long)]
    pub dry_run: bool,

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

    /// Only preview: sign in, list the folders and the messages' metadata
    /// (EXAMINE, UID FETCH of UID, FLAGS, INTERNALDATE, RFC822.SIZE) and print
    /// what would be acquired. Fetches no message body and writes nothing
    #[arg(long)]
    pub dry_run: bool,

    /// Print the result as JSON
    #[arg(long)]
    pub json: bool,
}

/// Sign-in and endpoints for Microsoft Graph (dfcollect graph, m365-logs)
#[derive(Args, Debug)]
pub struct GraphConnArgs {
    /// device: sign in as the account (device code, delegated permissions);
    /// app: application permissions, with the tenant's cooperation;
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

    #[command(flatten)]
    pub conn: GraphConnArgs,

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

    /// Only preview: sign in, list the folders and the messages' metadata and
    /// print what would be acquired. Fetches no message body and writes nothing
    #[arg(long)]
    pub dry_run: bool,

    /// Print the result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct M365LogsArgs {
    #[command(flatten)]
    pub conn: GraphConnArgs,

    /// Logs to read, comma-separated
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "signins,directory,ual",
        help_heading = "Logs"
    )]
    pub logs: Vec<crate::m365logs::LogKind>,

    /// Only these accounts (UPN, repeatable): sign-ins of them, directory
    /// changes they initiated, audit records of them. Default: the whole tenant
    #[arg(long = "user", value_name = "UPN", help_heading = "Logs")]
    pub users: Vec<String>,

    /// Unified Audit Log: only these record types, as Graph names them (e.g.
    /// exchangeItem, sharePointFileOperation; repeatable)
    #[arg(long = "record-type", value_name = "TYPE", help_heading = "Logs")]
    pub record_types: Vec<String>,

    /// Unified Audit Log: only these operations (e.g. MailItemsAccessed,
    /// FileDownloaded; repeatable)
    #[arg(long = "operation", value_name = "OPERATION", help_heading = "Logs")]
    pub operations: Vec<String>,

    /// Unified Audit Log: longest wait for the query to run, in minutes
    #[arg(long, default_value = "240", help_heading = "Logs")]
    pub ual_wait: u64,

    /// Unified Audit Log: seconds between status checks of the query
    #[arg(long, default_value = "30", hide = true)]
    pub ual_poll: u64,

    /// Start of the time window (RFC 3339, inclusive)
    #[arg(long, value_name = "TIME", help_heading = "Scope")]
    pub not_before: String,

    /// End of the time window (RFC 3339, exclusive)
    #[arg(long, value_name = "TIME", help_heading = "Scope")]
    pub not_after: String,

    /// Legal basis of the acquisition (order, date)
    #[arg(long, value_name = "TEXT", help_heading = "Scope")]
    pub legal_basis: Option<String>,

    /// New collection directory (on a target drive)
    #[arg(long, short = 'o', value_name = "DIR")]
    pub output: PathBuf,

    #[command(flatten)]
    pub case: CaseArgs,

    #[command(flatten)]
    pub clock: ClockArgs,

    /// Also compute MD5 for every log file
    #[arg(long, help_heading = "Hashes")]
    pub md5: bool,

    /// Also compute SHA-1 for every log file
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
pub struct CloudArgs {
    /// The rclone remote and path: REMOTE: or REMOTE:path (configure it with
    /// read-only scopes, e.g. Drive `scope = drive.readonly`)
    #[arg(value_name = "REMOTE:PATH")]
    pub source: String,

    /// rclone configuration file (default: rclone's own)
    #[arg(long, value_name = "FILE", help_heading = "rclone")]
    pub rclone_config: Option<PathBuf>,

    /// An extra rclone option for every call (repeatable), e.g.
    /// --rclone-arg=--drive-export-formats=docx,xlsx,pptx,pdf; recorded,
    /// secret-looking values removed
    #[arg(
        long = "rclone-arg",
        value_name = "ARG",
        allow_hyphen_values = true,
        help_heading = "rclone"
    )]
    pub rclone_args: Vec<String>,

    /// New collection directory (on a target drive)
    #[arg(long, short = 'o', value_name = "DIR")]
    pub output: PathBuf,

    #[command(flatten)]
    pub case: CaseArgs,

    /// Scope: --include/--exclude match the path below REMOTE:PATH; the time
    /// window applies to the modification time
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

    /// Deflate the container members
    #[arg(long, help_heading = "Output")]
    pub compress: bool,

    /// Accept a collection directory on a RAM-backed filesystem (tmpfs)
    #[arg(long, help_heading = "Safety")]
    pub allow_tmpfs: bool,

    /// Only preview: list the remote once (rclone lsjson), decide every file
    /// by the scope and print what would be acquired. Reads no file and
    /// writes nothing
    #[arg(long)]
    pub dry_run: bool,

    /// Print the result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DbArgs {
    /// postgres or mariadb (also MySQL)
    #[arg(value_enum, value_name = "ENGINE")]
    pub engine: crate::db::Engine,

    /// Server host name or address
    #[arg(long, help_heading = "Server")]
    pub host: String,

    /// Port (default: 5432 / 3306)
    #[arg(long, help_heading = "Server")]
    pub port: Option<u16>,

    /// User to connect as (read access to every database to dump)
    #[arg(long, short = 'u', help_heading = "Server")]
    pub user: String,

    /// File whose first line is the password (default: asked on the terminal)
    #[arg(long, value_name = "FILE", help_heading = "Server")]
    pub password_file: Option<PathBuf>,

    /// Connect without a password (peer, certificate or trust authentication)
    #[arg(long, conflicts_with = "password_file", help_heading = "Server")]
    pub no_password: bool,

    #[arg(long, value_enum, default_value = "prefer", help_heading = "Server")]
    pub tls: crate::db::Tls,

    /// Only this database (repeatable; default: all of them)
    #[arg(long = "database", value_name = "NAME", help_heading = "Scope")]
    pub databases: Vec<String>,

    /// Legal basis of the acquisition (order, date)
    #[arg(long, value_name = "TEXT", help_heading = "Scope")]
    pub legal_basis: Option<String>,

    /// PostgreSQL: a serializable, deferrable snapshot (waits for a safe moment)
    #[arg(long, help_heading = "Dump")]
    pub serializable: bool,

    /// MariaDB/MySQL: record the binary-log position (takes a brief global read lock)
    #[arg(long, help_heading = "Dump")]
    pub binlog_position: bool,

    /// New collection directory (on a target drive)
    #[arg(long, short = 'o', value_name = "DIR")]
    pub output: PathBuf,

    #[command(flatten)]
    pub case: CaseArgs,

    #[command(flatten)]
    pub clock: ClockArgs,

    /// Also compute MD5 for every dump
    #[arg(long, help_heading = "Hashes")]
    pub md5: bool,

    /// Also compute SHA-1 for every dump
    #[arg(long, help_heading = "Hashes")]
    pub sha1: bool,

    /// Deflate the container members
    #[arg(long, help_heading = "Output")]
    pub compress: bool,

    /// Accept a collection directory on a RAM-backed filesystem (tmpfs)
    #[arg(long, help_heading = "Safety")]
    pub allow_tmpfs: bool,

    /// Only preview: connect, ask the server for its version, clock and
    /// databases with their sizes, and print what would be dumped. Dumps
    /// nothing and writes nothing
    #[arg(long)]
    pub dry_run: bool,

    /// Print the result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct GmailArgs {
    /// Mailbox (`me` for --auth installed/token, or the user's email address for --auth service-account)
    #[arg(
        long,
        default_value = "me",
        value_name = "MAILBOX",
        help_heading = "Account"
    )]
    pub mailbox: String,

    /// installed: Desktop app OAuth 2.0 authorization code with PKCE;
    /// service-account: Google Workspace domain-wide delegation (--key-file, --mailbox);
    /// token: an access token from --token-file
    #[arg(
        long,
        value_enum,
        default_value = "installed",
        help_heading = "Account"
    )]
    pub auth: crate::gmail::GmailAuth,

    /// OAuth 2.0 Desktop app client ID (--auth installed)
    #[arg(long, value_name = "ID", help_heading = "Account")]
    pub client_id: Option<String>,

    /// File whose first line is the Desktop app client secret (--auth installed;
    /// default: asked on the terminal)
    #[arg(long, value_name = "FILE", help_heading = "Account")]
    pub client_secret_file: Option<PathBuf>,

    /// Service account JSON key file with private_key and client_email (--auth service-account)
    #[arg(long, value_name = "FILE", help_heading = "Account")]
    pub key_file: Option<PathBuf>,

    /// File whose first line is an access token with gmail.readonly (--auth token)
    #[arg(long, value_name = "FILE", help_heading = "Account")]
    pub token_file: Option<PathBuf>,

    /// Gmail API endpoint
    #[arg(
        long,
        default_value = "https://gmail.googleapis.com",
        value_name = "URL",
        help_heading = "Connection"
    )]
    pub gmail_endpoint: String,

    /// Google OAuth 2.0 token endpoint
    #[arg(
        long,
        default_value = "https://oauth2.googleapis.com/token",
        value_name = "URL",
        help_heading = "Connection"
    )]
    pub token_endpoint: String,

    /// Google OAuth 2.0 authorization endpoint (--auth installed)
    #[arg(
        long,
        default_value = "https://accounts.google.com/o/oauth2/v2/auth",
        value_name = "URL",
        help_heading = "Connection"
    )]
    pub auth_endpoint: String,

    /// Network timeout in seconds
    #[arg(long, default_value = "120", help_heading = "Connection")]
    pub timeout: u64,

    /// New collection directory (on a target drive)
    #[arg(long, short = 'o', value_name = "DIR")]
    pub output: PathBuf,

    #[command(flatten)]
    pub case: CaseArgs,

    /// Scope: --include/--exclude are matched against `<label>/<internalDate>Z-<id>`
    /// across every label on a message (excluded if any label matches an exclude,
    /// included if no includes or any label matches one); the time window applies
    /// to internalDate
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

    /// Only preview: sign in, list the messages and their metadata
    /// (format=minimal) and print what would be acquired. Fetches no message
    /// body and writes nothing
    #[arg(long)]
    pub dry_run: bool,

    /// Print the result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct IngestArgs {
    /// The delivered package: a directory, or a single file (an archive as delivered)
    #[arg(value_name = "PACKAGE")]
    pub package: PathBuf,

    /// Who delivered it (the provider)
    #[arg(long, help_heading = "Receipt")]
    pub provider: String,

    /// When it was received (RFC 3339)
    #[arg(long, value_name = "TIME", help_heading = "Receipt")]
    pub received_at: String,

    /// How it was received, e.g. "e-Evidence decentralised IT system", "SFTP",
    /// "courier, USB stick sealed 4711"
    #[arg(long, help_heading = "Receipt")]
    pub channel: String,

    /// The order's or the provider's reference
    #[arg(long, help_heading = "Receipt")]
    pub reference: Option<String>,

    /// A hash list the provider supplied (sha256sum/md5sum/sha1sum/sha512sum
    /// or BSD format; repeatable)
    #[arg(long = "hashes", value_name = "FILE", help_heading = "Checks")]
    pub hashes: Vec<PathBuf>,

    /// Accept files the hash lists don't name (otherwise they are errors)
    #[arg(long, help_heading = "Checks")]
    pub allow_unlisted: bool,

    /// Legal basis (the order, its date)
    #[arg(long, value_name = "TEXT", help_heading = "Receipt")]
    pub legal_basis: Option<String>,

    /// New collection directory (on a target drive)
    #[arg(long, short = 'o', value_name = "DIR")]
    pub output: PathBuf,

    #[command(flatten)]
    pub case: CaseArgs,

    #[command(flatten)]
    pub clock: ClockArgs,

    /// Also compute MD5 for every file
    #[arg(long, help_heading = "Hashes")]
    pub md5: bool,

    /// Also compute SHA-1 for every file
    #[arg(long, help_heading = "Hashes")]
    pub sha1: bool,

    /// Deflate the container members
    #[arg(long, help_heading = "Output")]
    pub compress: bool,

    /// Accept a collection directory on a RAM-backed filesystem (tmpfs)
    #[arg(long, help_heading = "Safety")]
    pub allow_tmpfs: bool,

    /// Only preview: list the package, read the hash lists and print what
    /// would be taken (names and sizes). Reads no file content and writes
    /// nothing
    #[arg(long)]
    pub dry_run: bool,

    /// Print the result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct VerifyArgs {
    /// Collection directory
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,

    /// Print the result as JSON
    #[arg(long)]
    pub json: bool,
}
