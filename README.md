# dfcollect

Logical acquisition for forensic examiners: copies what a warrant covers, and
only that, from a mounted source into a verifiable container, with a manifest
that records what was taken, what was left out and how.

dfcollect is part of the dfnix tool suite, alongside dfdisk (disk imaging),
dfmount (read-only mounts), dfnet (network shares and streams) and dfcore
(shared safety core and audit log). Where dfdisk images whole devices,
dfcollect acquires files, mailboxes (IMAP, Microsoft 365), Microsoft 365 logs
and cloud data, and later databases.

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
   (`--exclude "X/**"`) is not even listed. Files outside the scope are only
   counted by reason, so no names outside the warrant end up in the records.
   `--list-out-of-scope` lists them by name instead.
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
| 8 | Stopped by a signal (Ctrl+C); everything acquired so far is recorded and verifiable |

## Building

```bash
cargo build --release      # needs ../dfcore next to this repository
nix build                  # dfcore from the flake input
```

## License

Dual-licensed under MIT and Apache-2.0.
