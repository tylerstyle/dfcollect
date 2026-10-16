# dfcollect

Logical acquisition for forensic examiners: copies what a warrant covers, and
only that, from a mounted source into a verifiable container, with a manifest
that records what was taken, what was left out and how.

dfcollect is part of the dfnix tool suite, alongside dfdisk (disk imaging),
dfmount (read-only mounts), dfnet (network shares and streams) and dfcore
(shared safety core and audit log). Where dfdisk images whole devices,
dfcollect acquires files, and later mail, cloud data and databases.

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
