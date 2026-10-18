# dfcollect

Logical acquisition for forensic examiners: copies what a warrant covers, and
only that, from a mounted source into a verifiable container, with a manifest
that records what was taken, what was left out and how.

dfcollect is part of the dfnix tool suite, alongside dfdisk (disk imaging),
dfmount (read-only mounts), dfnet (network shares and streams) and dfcore
(shared safety core and audit log). Where dfdisk images whole devices,
dfcollect acquires files, mailboxes (IMAP, Microsoft 365, Gmail), Microsoft 365
logs, cloud data and databases, and takes in provider deliveries.

## What `dfcollect files` does

```bash
dfcollect files /media/evidence/sdb1/Users/anna \
  -o /media/target/case01/anna-docs \
  -C "VG 12345/26" -E docs01 -e "KHK Muster" \
  --legal-basis "AG Musterstadt 12 Gs 34/26 of 2026-10-01" \
  --include "Documents/**" --exclude "Documents/Private/**" \
  --not-before 2026-01-01T00:00:00+01:00 --not-after 2026-07-01T00:00:00+02:00
```

1. **Checks before anything is written.** The source must be a directory on a
   read-only mount: a dfmount evidence mount or a dfnet SMB/NFS share. The
   collection directory must be new or empty, not inside the source, not on
   the source's physical disk, and not in RAM.
2. **Decides by scope first.** Every entry is checked against the scope before
   any of its content is read: path patterns (`*` and `?` within a folder, `**`
   across folders; excludes win), a time window on modified, accessed, changed
   or birth time, and the legal basis. An excluded folder tree
   (`--exclude "X/**"`) is not even listed, and neither is a folder that no
   `--include` pattern can reach (with `--include "Documents/**"`, the folder
   `Music` is counted once as "directory tree matches no include pattern").
   Files outside the scope are only counted by reason, so no names outside the
   warrant end up in the records. `--list-out-of-scope` lists them by name
   instead.
3. **Copies into one container.** In-scope files go into `data.zip` (ZIP64,
   stored, or deflated with `--compress`). Each member carries its modified,
   accessed and created times in the NTFS timestamp field, which the analysis
   suites read. A ZIP container keeps every file name intact on exFAT and NTFS
   target drives, which would otherwise mangle or merge some Linux names.
4. **Hashes while reading.** dfcollect computes SHA-256 for every file (`--md5`
   and `--sha1` add those). Files are opened without following symlinks and,
   where permitted, without updating their access time. A file that changes
   while it is read is flagged. On a network share, dfcollect records whether
   the server updated access times.
5. **Verifies.** When the copy is done, dfcollect reads the container back and
   hashes every member again.
6. **Records everything.** See [The collection directory](#the-collection-directory).

**Preview first: `--dry-run`.** The same command with `--dry-run` runs every
check above, then walks the source with the same scope decisions and prints what
a run would acquire: files, bytes, folders and symlinks in scope, everything
else counted by reason, folders where another filesystem is mounted, entries
that cannot be read, and whether the target has room. It reads only folder
listings and file metadata, opens no file, and writes nothing: no collection
directory, no audit record. Names outside the scope are never shown, whatever
`--list-out-of-scope` says. A run started from the TUI after a preview notes
the preview in its footprint.

**Progress.** On a terminal, `files` and `verify` show a progress line on
stderr (not with `--json`).

## Terminal UI

Running `dfcollect` without arguments on a terminal opens the interactive TUI
for all eight acquisition modes (`files`, `ingest`, `cloud`, `db`, `imap`,
`graph`, `gmail`, `m365-logs`) and `verify` (when `stdin` or `stdout` is not a
terminal, `dfcollect` prints the command-line help and exits 2). The TUI uses
the standard 16 ANSI colours and fits 80×24 serial and Linux virtual consoles
without mouse capture, so paths and hashes stay selectable.

1. **Home.** Choose **Acquire files from a mounted directory** (`dfcollect files`),
   **Verify a collection** (`dfcollect verify`), **Provider delivery package**
   (`dfcollect ingest`), **Cloud / remote storage (rclone)** (`dfcollect cloud`),
   **Database dump (PostgreSQL / MariaDB)** (`dfcollect db`), **IMAP mailbox**
   (`dfcollect imap`), **Microsoft 365 mailbox (Graph)** (`dfcollect graph`),
   **Gmail / Google Workspace mailbox** (`dfcollect gmail`) or **Microsoft 365 tenant audit logs**
   (`dfcollect m365-logs`).
2. **Mode forms.** Every acquisition form shares case metadata (`--case`,
   `--evidence`, `--examiner`, `--description`, `--notes`), target output
   suggestion (`/media/target/<mount>/<case>/<evidence>` with path-safe
   characters and live free-space check), reference clock (type the trusted
   clock's time a few seconds ahead and press `Enter` when the clock shows it to
   stamp the local clock), hashes (`--md5`, `--sha1`), compression, and safety
   overrides (`--allow-tmpfs`, `--allow-writable-source`, `--allow-unlisted`,
   each requiring confirmation):
   - **Files (`dfcollect files`).** Pick a read-only source mount (dfmount
     evidence under `/media/evidence/*` first, then read-only dfnet shares, or
     type a path with `F4`/`Tab` autocompletion), and set the warrant scope
     (legal basis, `--include` / `--exclude` glob lists, RFC 3339 time window
     with live UTC hints, or a `--scope` JSON file).
   - **Provider delivery (`dfcollect ingest`).** Select the delivered package
     file or directory, enter `--provider`, `--received-at` (RFC 3339 with live
     UTC hint), optional `--channel`, `--reference`, companion `--hashes` sum
     files, `--allow-unlisted` and `--legal-basis`.
   - **Cloud (`dfcollect cloud`).** Pick a pre-configured remote discovered via
     `rclone listremotes --long` (secrets in `rclone.conf` are never read by the
     form), edit `REMOTE:path`, optional `--rclone-config` and safe read-only
     `--rclone-arg` flags, and set the warrant scope (modification-time window,
     include/exclude globs or `--scope` JSON file).
   - **Database (`dfcollect db`).** Choose `postgres` or `mariadb`, set `--host`,
     `--port` (`5432` / `3306` defaults), `--user`, `--password-file` or
     `--no-password` (or leave both unset to be prompted in a masked modal on
     preview/run), `--tls`, optional `--database` list, `--legal-basis`, and the
     engine-specific option (`--serializable` for PostgreSQL,
     `--binlog-position` for MariaDB/MySQL).
   - **IMAP mailbox (`dfcollect imap`).** Set the positional `SERVER` (`host`,
     `host:port` or `[IPv6]:port`), `-u` / `--user`, `--auth` (`auto` default,
     `plain`, `login`, `xoauth2`), optional `--password-file` or `--token-file`
     (or leave unset for the masked modal), `--security` (`tls` on port 993,
     `start-tls` on port 143, or `plaintext`), optional `--tls-sha256` pin,
     optional `--timeout`, and warrant scope (`INTERNALDATE` time window,
     folder/message globs, `--unknown-time` or `--scope`).
   - **Microsoft 365 mailbox (`dfcollect graph`).** Set `--mailbox` (UPN,
     address or `me` default), `--auth` (`device`, `app`, `token`), `--tenant`
     (`organizations` default), `--client-id`, optional `--client-secret-file`
     or `--token-file` (or masked modal), national cloud endpoints
     (`--graph-endpoint` and `--login-endpoint`, set in the TUI via the Cloud
     preset for Global, US Gov L4, US Gov DoD, China 21Vianet or Custom, and
     omitted from argv when global defaults are used; Recoverable
     Items/Deletions are always read), and warrant scope (`receivedDateTime`
     time window, folder globs, `--unknown-time` or `--scope`).
   - **Gmail / Google Workspace mailbox (`dfcollect gmail`).** Set `--mailbox`
     (address or `me` default), `--auth` (`installed`, `service-account`, `token`),
     the credentials for that auth mode (`--client-id` and optional
     `--client-secret-file` for `installed`; `--key-file` and `--mailbox` for
     `service-account`; `--token-file` for `token`; or entered in the masked
     secret modal), optional custom endpoints (`--gmail-endpoint`,
     `--token-endpoint`, `--auth-endpoint`), optional `--timeout`, and
     warrant scope (`internalDate` time window, label globs, `--unknown-time` or
     `--scope`).
   - **Microsoft 365 tenant audit logs (`dfcollect m365-logs`).** Set `--tenant`,
     `--auth` (`device` default, `app`, `token`), `--client-id`, optional
     `--client-secret-file` or `--token-file` (or masked modal), national cloud
     endpoints (`--graph-endpoint` and `--login-endpoint`, filled from the
     form's Cloud preset), log toggles with `--logs` (`signins`, `directory`,
     `ual`), required time window (`--not-before` and `--not-after`, with the
     form showing the whole-second UTC window `Rounded UAL window: start .. end`
     where start is rounded down and end rounded up so the window never shrinks),
     optional `--user` (repeatable UPN filter), `--record-type`, `--operation`,
     `--ual-wait` (minutes) and `--legal-basis`. Because Purview Unified Audit Log
     searches create an asynchronous server-side query job in the tenant
     (`POST /security/auditLog/queries`), `m365-logs` has no dry-run preview; an
     inline query summary is shown on the form and `F2` / `p` opens the start
     confirmation modal (`Modal::ConfirmStart`) directly.

   The bottom line always shows the equivalent `dfcollect <mode> …` CLI command
   live (passwords, tokens and secrets are never placed in `argv`).
3. **Interactive Sign-In & Masked Secret Modal.** When a mode needs a password,
   client secret or bearer token and no credential file is set, a masked modal
   (`•` bullets, held in `Zeroizing<String>`) asks once during preview and
   reuses the secret for the acquisition run. For OAuth 2.0 flows (`graph --auth device`,
   `m365-logs --auth device`, `gmail --auth installed`), a full-size **Sign-In**
   screen displays either:
   - **Device code (`SignIn::DeviceCode`):** verification URI (`u` copies URI
     via OSC 52) and user code (`y` copies code via OSC 52) with instructions
     and live expiry countdown.
   - **Browser authorization (`SignIn::Browser`):** wrapped OAuth 2.0 + PKCE
     authorization URL (`u` or `F2` copies URL via OSC 52) together with the
     `127.0.0.1` loopback listener address and a paste field for the full
     redirect URL (including `code` and `state`) when signing in from another
     device.

   Pressing `Esc` opens `"Stop signing in?"` (`Modal::ConfirmStopSignIn`);
   confirming with `y` stops a preview cleanly or ends an acquisition run as
   aborted (exit 8). Credentials and OAuth tokens obtained during preview are
   preserved and handed over to the acquisition run so signing in is only done
   once; they are cleared when connection or auth fields change, when switching
   modes, on next acquisition (`n`), or on quit (`q`). `m365-logs` has no dry-run
   preview and signs in during its run.
4. **Preview (`F2` or `p`).** Runs the active mode in `--dry-run` mode on a
   background thread (`Esc` or `s` stops early):
   - `files`: in-scope counts and bytes, target free space, out-of-scope counts
     by reason, unlisted excluded/unreachable trees, other filesystems, walk
     errors and up to 1000 in-scope sample paths.
   - `ingest`: package kind, provider receipt metadata, companion hash-list
     verification summary (listed present, missing, unlisted) and entries.
   - `cloud`: remote and provider hash types, in-scope vs listed objects and
     bytes, out-of-scope counts by reason (never out-of-scope object names) and
     in-scope sample objects.
   - `db`: server and dumper versions, server clock, per-database estimated
     bytes and target free space.
   - `imap`: server greeting and authentication method, target free space,
     folders with in-scope and total message counts and bytes, skipped folders
     with their skip reasons, time basis (`IMAP INTERNALDATE`), and out-of-scope
     counts (internal attributes and `UIDVALIDITY` are recorded in the run's
     footprint).
   - `graph`: mailbox account, authentication method, tenant, cloud endpoint,
     target free space, folders with in-scope message counts and bytes (including
     Recoverable Items / Deletions), skipped folders with reasons, time basis
     (`receivedDateTime`), and out-of-scope counts.
   - `gmail`: mailbox account, authentication method, in-scope vs listed message
     counts and bytes, target free space, per-label breakdown with message counts
     and bytes, time basis (`Gmail internalDate`), and out-of-scope counts
     (account `historyId` is recorded in the run's footprint).

   Press `c` to copy the equivalent CLI command via OSC 52. Starting an
   acquisition (`Enter` or `F2`/`p` on m365-logs → `y`) is only possible when
   the preview is complete and matches the form.
5. **Run.** Shows the phase line (`Phase: 1. Copying  →  2. Checking container  →  3. Finishing`,
   or for `m365-logs`: `Phase: 1. Waiting  →  2. Checking container  →  3. Finishing`)
   and active sub-stage (`Stage : …`), a progress gauge, items acquired,
   out-of-scope and error counts, elapsed time, and live notices pane (`l`
   expands/collapses the full scrollable 50-entry notice log). For streaming and
   copying modes, it shows a 5-second rolling transfer rate, ETA, and current
   item; for `m365-logs`, it shows `Logs`, `Records`, and `Bytes written` instead
   of rate and ETA. Pressing `s` or `Ctrl+C` (confirmed with `y`) stops the
   acquisition cleanly (`aborted`, `"stopped by the examiner"`, exit 8); quitting
   directly with `q` is disabled while running.
6. **Result & Verify.** Shows the final status and exit-code meaning, collection
   path, totals (including both log and record counts for `m365-logs`),
   aligned mode-specific summary fields, 64-hex audit anchor on its own line,
   the full equivalent CLI command (press `c` to copy via OSC 52; when the
   command exceeds available space at 80×24, an explicit copy marker is shown
   so problems stay visible), and scrollable problems and warnings. On runs with
   errors, the problems pane lists failed items from `items.jsonl` (the first
   20, followed by `+N more in items.jsonl`). Press `v` to verify the collection
   immediately, `n` to start the next acquisition in the same case (keeping case,
   examiner, source/connection, scope and options, and clearing evidence,
   description, notes, reference clock, safety overrides and cached credentials),
   or `q` to quit.

**What it records.** A collection started from the TUI records the equivalent
`dfcollect <mode> …` command in `manifest.json` (`method.argv`), plus
`footprint.jsonl` entries: `"started from the dfcollect TUI; method.argv is the equivalent command line"`
and (for the seven modes with `--dry-run`) the mode's preview note
(`Preview::note()` / `IngestPreview::note()` / `CloudPreview::note()` /
`DbPreview::note()` / `ImapPreview::note()` / `GraphPreview::note()` /
`GmailPreview::note()`) with the preview timestamp (`at`), plus a note when a
credential entered or obtained during preview was reused for the run. When a
reference clock reading is given, pressing `Enter` on the field stamps the local
clock at that moment (`clocks.reference.local`), so `offset_seconds` reflects
the offset when the reading was taken rather than when the run started.

## What `dfcollect imap` does

```bash
dfcollect imap mail.example.org --user anna@example.org --password-file /run/pw \
  -o /media/target/case01/anna-mail \
  -C "VG 12345/26" -E mail01 -e "KHK Muster" \
  --legal-basis "AG Musterstadt 12 Gs 34/26 of 2026-10-01" \
  --include "INBOX/**" --include "Sent/**" --exclude "INBOX/Spam/**" \
  --not-before 2026-01-01T00:00:00+01:00 --not-after 2026-07-01T00:00:00+02:00
```

1. **Read-only by protocol.** Folders are opened with `EXAMINE`, never
   `SELECT`, and dfcollect stops if the server does not confirm `[READ-ONLY]`.
   Bodies are fetched with `BODY.PEEK[]`, which leaves `\Seen` and every other
   flag untouched.
2. **Scope before download.** A folder an exclude pattern removes
   (`Folder/**`), or that no include pattern can match, is never opened. In the
   other folders, dfcollect first fetches only UID, flags, INTERNALDATE and
   size. It decides every message on its folder, the account and its
   INTERNALDATE before fetching its body. Include and exclude patterns match
   `<folder>/<uid>`, with `/` between folder levels whatever separator the
   server uses.
3. **Byte for byte.** Each message is stored exactly as the server sends it, as
   `<folder>/<uid>.eml` in `data.zip`. Its item records UIDVALIDITY, UID,
   flags, INTERNALDATE, RFC822.SIZE and the hashes.
4. **The connection is evidence too.** The TLS version, cipher and the
   server's certificates (saved under `tls/`) are recorded. So are the greeting,
   the capabilities, the authentication method (never the secret), every
   command sent and the bytes in both directions.
5. **TLS.** dfcollect connects with TLS (port 993) or STARTTLS (143) and checks
   the server against the system's CAs. For a server with an internal CA,
   compare its fingerprint on a trusted channel and pass `--tls-sha256`.
   `--security plaintext` exists for test setups.
6. **Accounts.** The password comes from `--password-file` or is asked on the
   terminal. `--token-file` with `--auth xoauth2` uses an OAuth 2.0 access
   token, for example for Microsoft 365 or Gmail over IMAP.

Logging in can make the provider notify the account owner ("new sign-in"),
which can tip off a suspect. Prefer provider orders where that matters.

## What `dfcollect graph` does

Microsoft 365 (Exchange Online) mailboxes through Microsoft Graph. Exchange Web
Services is being switched off in Exchange Online, so EWS-based tools stop
working; Graph is the way in.

```bash
dfcollect graph --client-id 00000000-0000-0000-0000-000000000000 --tenant contoso.onmicrosoft.com \
  -o /media/target/case01/anna-m365 \
  -C "VG 12345/26" -E mail02 -e "KHK Muster" \
  --exclude "Junk Email/**" \
  --not-before 2026-01-01T00:00:00+01:00 --not-after 2026-07-01T00:00:00+02:00
```

1. **Sign-in.** You need an app registration of your own (the client id):
   - `--auth device` (the default): someone signs in as the account holder with
     a device code, on any device with a browser. The registration must allow
     public client flows and have the delegated permission `Mail.Read`. The
     token is renewed with `offline_access` during long runs.
   - `--auth app`: with the tenant's cooperation. The admin grants the
     application permission `Mail.Read`; give `--tenant`,
     `--mailbox user@domain` and the secret with `--client-secret-file`.
   - `--auth token`: an access token from `--token-file`, obtained some other
     way. It is not renewed.

   Tokens and secrets stay in memory. The record holds the method, the client,
   the tenant, the granted scopes, and the claims in the token that name the
   account and the app.
2. **Read-only by API.** Only GET requests go to Graph, so nothing in the
   mailbox changes, `isRead` included. dfcollect sends the token to the Graph
   endpoint only; a paging link to another host is refused.
3. **Every folder.** All levels and hidden folders, plus Recoverable Items
   (deletions). Search folders are skipped, since they only point at other
   folders.
4. **Scope before download.** Each folder's message metadata is fetched first.
   Every message is then decided on its folder and its `receivedDateTime` before
   its body is fetched. Patterns match `<folder>/<received>Z-<id hash>`, with
   `/` between folder levels; a `/` inside a folder name is written `%2F`.
5. **What is stored.** Each body is stored as Exchange's MIME rendition
   (`/messages/{id}/$value`), as `<folder>/<received>Z-<id hash>.eml`. Exchange
   converts the stored item to MIME, so the bytes need not be those once
   received; the manifest says so. Each item carries Graph's metadata:
   - the immutable id, so it stays stable when a message moves;
   - Internet message id, sender and recipients, the times, `isRead`, flags and
     categories;
   - Exchange's own size of the item.
6. **The connection is evidence too.** The TLS sessions with their
   certificates (saved under `tls/`) are recorded, and so are the requests and
   the bytes in both directions. So are the waits when Graph throttles (429,
   `Retry-After`) and the token renewals.
7. **National clouds.** `--graph-endpoint` and `--login-endpoint`.

On the tenant's side the sign-in is logged, and Exchange may log
MailItemsAccessed in the Unified Audit Log. A sign-in as the account holder can
notify them. Prefer provider orders or the tenant's cooperation where that
matters.

## What `dfcollect m365-logs` does

The logs of a Microsoft 365 tenant for a time window. They expire sooner than
the data, so take them first:

- Entra sign-in logs. These need Entra ID P1/P2 and are kept for 30 days.
- Entra directory audits.
- The Unified Audit Log (Purview Audit): MailItemsAccessed, file access,
  mailbox audit and more.

```bash
dfcollect m365-logs --auth app --tenant contoso.onmicrosoft.com --client-id <app id> \
  --client-secret-file /run/secret \
  --not-before 2026-03-01T00:00:00+01:00 --not-after 2026-04-01T00:00:00+02:00 \
  --user anna@contoso.com \
  -o /media/target/case01/m365-logs -C "VG 12345/26" -E logs01 -e "KHK Muster"
```

1. **Permissions.** Usually the tenant cooperates (`--auth app`); the admin
   grants your app `AuditLog.Read.All`, `Directory.Read.All` and
   `AuditLogsQuery.Read.All`. With `--auth device`, an account holding a
   reader role (e.g. Global Reader, Security Reader) signs in. dfcollect asks
   only for the permissions the chosen `--logs` need.
2. **Filtered on the server.** Every log is filtered by the time window (whole
   seconds: the start rounded down, the end up) and, with `--user`, by account:
   sign-ins of the account, directory changes it initiated, audit records of it.
   `--record-type` and `--operation` narrow the audit log further.
3. **The audit log is a query.** dfcollect creates an audit log query in the
   tenant (`POST /security/auditLog/queries`). This is its only write, recorded
   in the footprint with the query's id. It waits for the query to run
   (`--ual-wait`, default 4 hours) and then reads the records.
4. **Stored as they came.** Each log is one member `logs/<log>.jsonl` of
   `data.zip`, one record per line. Its item carries the record count, the
   filter, the window, and for the audit log the query.
5. **One refusal doesn't stop the rest.** A log the tenant refuses (missing
   licence or permission) fails as its own item; the other logs are still
   read, and the collection ends complete with errors.

## What `dfcollect cloud` does

Files from cloud and remote services through rclone: OneDrive, SharePoint,
Google Drive, Dropbox, S3, WebDAV/Nextcloud, SFTP, Box and rclone's other
backends. Configure the remote first with read-only access where the provider
offers it: Drive `scope = drive.readonly`; OneDrive `access_scopes = Files.Read
Files.Read.All Sites.Read.All offline_access`; read-only S3 credentials.

```bash
dfcollect cloud evidence-drive:Projects --rclone-config /media/target/case01/rclone.conf \
  -o /media/target/case01/drive -C "VG 12345/26" -E cloud01 -e "KHK Muster" \
  --not-before 2026-01-01T00:00:00+01:00 --not-after 2026-07-01T00:00:00+02:00
```

1. **Read only.** Only `rclone lsjson` and `rclone cat` touch the remote, and
   both only read. rclone's version and the remote's configuration are
   recorded; tokens, secrets, passwords and keys are removed.
2. **Listed before and after.** `lsjson -R --hash --metadata` lists the remote
   with the provider's hashes, IDs and metadata before and after the
   acquisition. Both listings are members of `data.zip` (`rclone/`). Files
   added, removed or changed in between are recorded, and the collection ends
   complete with errors.
3. **Scope before download.** Include and exclude patterns match the path
   below the given remote path; the time window applies to the modification
   time. Out-of-scope files are never read.
4. **Checked against the provider.** Each file is streamed from `rclone cat`
   into `files/<path>`. On the way dfcollect computes SHA-256 (MD5 and SHA-1 on
   request) and every provider hash it knows: MD5, SHA-1, OneDrive's
   QuickXorHash, Dropbox's content hash. It compares them with the listing; a
   difference, a size mismatch or a failed `rclone cat` makes the file's item
   an error, which says what differed.
5. **Google-native documents** (Docs, Sheets, Slides) are exported by rclone.
   Pass the formats with `--rclone-arg=--drive-export-formats=docx,xlsx,pptx,pdf`.
   Every extra rclone option is recorded.

## What `dfcollect db` does

Consistent logical dumps of PostgreSQL and MariaDB/MySQL servers, made with the
database's own tools:

```bash
dfcollect db postgres --host db.example.org --user examiner --password-file /run/pw \
  -o /media/target/case01/db -C "VG 12345/26" -E db01 -e "KHK Muster"
dfcollect db mariadb --host 10.0.0.5 --user examiner --database shop --tls require ...
```

1. **Consistent dumps.**
   - PostgreSQL: `pg_dump --format=custom` per database, one read-only
     snapshot each (restore with `pg_restore`; `--serializable` waits for a
     safe snapshot), and `pg_dumpall --globals-only` for roles and tablespaces,
     without role password hashes.
   - MariaDB/MySQL: `mariadb-dump --single-transaction --routines --triggers
     --events --hex-blob` per database, consistent for InnoDB without locks.
     `--binlog-position` adds the binary-log coordinates at the cost of a brief
     global read lock.
2. **The server is recorded:** version, time zone and clock (`now()` on the
   server, next to dfnix's), start time, databases with sizes, encodings and
   collations, and the number of sessions.
3. **Streamed.** Each dump goes straight into `data.zip`
   (`postgres/<db>.dump`, `mariadb/<db>.sql`) and is hashed. A tool that fails
   leaves an error item that says why.
4. **The password** comes from `--password-file` or the terminal. It reaches
   the tools in a 0600 file in a private directory in RAM (`.pgpass` / an option
   file), never on the command line or the target drive, and is deleted
   afterwards.
5. **Footprint.** The connections appear in the server's logs and session
   views. pg_dump holds ACCESS SHARE locks, so DDL waits while it runs.
6. **What a dump doesn't show.** A logical dump shows the current state only.
   Deleted rows survive in data files and in WAL/binlog. For those, add a
   file-level copy (from a filesystem snapshot) or the disk image.
## What `dfcollect gmail` does

Google Workspace and Gmail mailboxes through the Gmail API (`gmail.readonly`,
`format=raw`). Unlike Gmail over IMAP, where a message with several labels is
listed in several folders, the Gmail API stores each message once with all its
labels recorded.

```bash
dfcollect gmail --auth service-account --key-file /run/sa.json \
  --mailbox anna@contoso.org \
  -o /media/target/case01/anna-gmail \
  -C "VG 12345/26" -E mail03 -e "KHK Muster" \
  --exclude "SPAM/**" \
  --not-before 2026-01-01T00:00:00+01:00 --not-after 2026-07-01T00:00:00+02:00
```

1. **Sign-in (`--auth`):**
   - `--auth service-account` (Google Workspace, with the admin's cooperation
     and domain-wide delegation): give `--key-file sa.json` and
     `--mailbox user@domain`. dfcollect signs an RS256 JWT assertion with the
     service account's private key for scope
     `https://www.googleapis.com/auth/gmail.readonly` and renews it during long
     runs.
   - `--auth installed` (the default; the account holder signs in): give
     `--client-id` and `--client-secret-file` of a Desktop app OAuth client.
     dfcollect runs the authorization-code flow with PKCE (`S256`) and prints
     the authorization URL; it accepts the redirect either on its `127.0.0.1`
     loopback listener (browser on dfnix) or when the full redirect URL is
     pasted on `stdin` (browser on another device), verifies `state`, and
     renews with the refresh token.
   - `--auth token`: an access token with `gmail.readonly` from `--token-file`
     (not renewed).
2. **Read-only by API.** Only GET requests reach the Gmail API, and the
   `gmail.readonly` scope cannot modify messages, labels or `UNREAD`. The token
   is sent only to `--gmail-endpoint`.
3. **Labels are not folders.** Every message (including `SPAM` and `TRASH`,
   `includeSpamTrash=true`) is listed first, then its minimal metadata
   (`?format=minimal`: `labelIds`, `internalDate`, `sizeEstimate`, `threadId`,
   `historyId`) is fetched. Each in-scope message is stored once under its
   first label in the order `INBOX`, `SENT`, `DRAFT`, `SPAM`, `TRASH`, then
   user labels by name, else `All Mail`, as
   `<label>/<internalDate compact>Z-<id>.eml` in `data.zip`.
4. **Scope before download.** The time window applies to `internalDate`
   (`"time_basis": "internalDate"`). Include and exclude patterns are matched
   against `<label>/<internalDate compact>Z-<id>` once for every label the
   message carries:
   - excluded if any label path matches an exclude pattern (e.g. `SPAM/**`);
   - otherwise included if there are no includes, or if any label path matches
     one.
5. **Exact RFC 2822 bytes.** For in-scope messages, `?format=raw` returns the
   exact RFC 2822 message bytes. Each item carries `id`, `threadId`, `labels`
   (IDs and names), `internalDate` (RFC 3339), `sizeEstimate` and `historyId`.
6. **Footprint.** Google Workspace logs OAuth token grants for service accounts
   in the Token Audit Log; an `installed` sign-in can send a "new sign-in" or
   "third-party access" alert to the account holder.

## What `dfcollect ingest` does

Takes a data package a provider delivered into a verifiable collection: a
European Production Order answered under Regulation (EU) 2023/1543 (in force
since 18 August 2026), a provider export, a delivery on media.

```bash
dfcollect ingest /media/evidence/delivery-0815 --hashes /media/evidence/delivery-0815.sha256 \
  --provider "Example Mail GmbH" --received-at 2026-10-16T10:00:00+02:00 \
  --channel "e-Evidence decentralised IT system" --reference "EPOC 2026/123" \
  -o /media/target/case01/delivery -C "VG 12345/26" -E prov01 -e "KHK Muster"
```

1. **The receipt** is recorded: provider, time of receipt, channel, reference,
   examiner.
2. **Every file of the package**, a directory or a single delivered file, is
   stored in `data.zip` (`package/<path>`), as it is, and hashed. Symlinks are
   recorded, not followed.
3. **The provider's hash lists** (`sha256sum`, `md5sum`, `sha1sum`, `sha512sum`
   output, or BSD `SHA256 (path) = …`) are stored as `provider/<name>`, and
   every file is checked against them. A file that differs or is missing is an
   error. So is a file the lists don't name, unless `--allow-unlisted`. The
   summary counts verified, mismatched, missing and unlisted files.

## The collection directory

| File | Content |
| --- | --- |
| `manifest.json` | case, source (mount, device), method (tool version, system revision, command line, read-only means), scope, clocks, totals, audit anchor |
| `items.jsonl` | one line per item: path, status (`acquired`, `out_of_scope`, `error`, `skipped`), kind, size, hashes, all timestamps with nanoseconds, mode, owner, inode, extended attributes and ACLs, symlink targets |
| `footprint.jsonl` | what the source could see or what changed on it |
| `items.csv` | the items as a court annex (UTF-8 with BOM, opens in Excel) |
| `data.zip` | the acquired files |
| `audit-<boot>.jsonl` | the dfnix audit log with the start and finish records |

The chain of integrity runs from the data to the audit log:

1. Every item carries its SHA-256.
2. The finished manifest carries the SHA-256 of `items.jsonl`,
   `footprint.jsonl` and `items.csv`.
3. The audit record `logical_collection_finished` carries the SHA-256 of
   `manifest.json`, and the manifest names the hash of the
   `logical_collection_started` record.

`dfcollect verify DIR` checks all of it.

## Scope files

Instead of the scope options, pass a JSON file with `--scope`. A misspelt field
is an error, never a silently wider scope:

```json
{
  "legal_basis": "AG Musterstadt 12 Gs 34/26 of 2026-10-01",
  "include": ["Documents/**", "Desktop/*.pdf"],
  "exclude": ["Documents/Private/**"],
  "not_before": "2026-01-01T00:00:00+01:00",
  "not_after": "2026-07-01T00:00:00+02:00",
  "time_basis": "mtime",
  "unknown_time": "exclude"
}
```

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Complete: every in-scope item was acquired and the container verified (`verify`: everything matches) |
| 2 | Usage error (invalid options or scope); nothing was written |
| 3 | Refused by a safety check; nothing was written |
| 4 | Failed to run (`verify`: a check could not run, or audit anchors are missing) |
| 5 | The container or the records do not match |
| 6 | Incomplete: the container could not be written (e.g. the target is full) |
| 7 | Complete, but items failed (read errors, files changed while read) |
| 8 | Stopped by a signal (Ctrl+C) or, in the TUI, by the examiner; everything acquired so far is recorded and verifiable. A file being copied at that moment is left out, not recorded half |

## Building

```bash
cargo build --release      # needs ../dfcore next to this repository
nix build                  # dfcore from the flake input
```

## License

Dual-licensed under MIT and Apache-2.0.
