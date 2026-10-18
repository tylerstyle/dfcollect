#!/usr/bin/env python3
"""A tiny IMAP4rev1 server over TLS for testing (invented data).
LOGIN only (password "invented-imap-pw"), LIST, EXAMINE (always [READ-ONLY]),
UID FETCH metadata and BODY.PEEK[], LOGOUT. Logs every command to LOG."""
import argparse, os, re, socket, ssl, sys, threading

parser = argparse.ArgumentParser(description="IMAP4rev1 TLS mock server")
parser.add_argument("port", type=int, help="Port to listen on (0 for dynamic)")
parser.add_argument("cert", help="Path to TLS certificate")
parser.add_argument("key", help="Path to TLS private key")
parser.add_argument("log", help="Path to request log")
parser.add_argument("--bind", default="127.0.0.1", help="Host/IP to bind to")
parser.add_argument("--port-file", help="File to write bound port to")
parser.add_argument("--password", default="invented-imap-pw", help="Expected password")

args = parser.parse_args()
PORT = args.port
CERT = args.cert
KEY = args.key
LOG = args.log
BIND_HOST = args.bind
PASSWORD = args.password


def msg(n, subject):
    return (
        f"From: bob@example.org\r\nTo: alice@example.org\r\nSubject: {subject}\r\n"
        f"Date: Sun, 01 Mar 2026 10:00:00 +0000\r\nMessage-ID: <{n}@example.org>\r\n\r\nBody {n}\r\n"
    ).encode()


FOLDERS = {
    "INBOX": [
        (1, "\\Seen", "01-Mar-2026 10:00:00 +0000", msg(1, "Hello")),
        (2, "", "02-Mar-2026 10:00:00 +0000", msg(2, "Invoice")),
    ],
    "Sent": [(7, "\\Seen", "03-Mar-2026 10:00:00 +0000", msg(7, "Re: Invoice"))],
}
LIST = [
    '* LIST (\\HasNoChildren) "/" INBOX',
    '* LIST (\\HasNoChildren) "/" Sent',
    '* LIST (\\Noselect \\HasChildren) "/" Archive',
]
lock = threading.Lock()


def log(line):
    with lock, open(LOG, "a") as f:
        f.write(line + "\n")


def serve(conn):
    f = conn.makefile("rwb")

    def out(s):
        f.write(s if isinstance(s, bytes) else (s + "\r\n").encode())
        f.flush()

    out("* OK [CAPABILITY IMAP4rev1] mock ready")
    authed, folder = False, None
    while True:
        line = f.readline()
        if not line:
            return
        text = line.decode(errors="replace").rstrip("\r\n")
        tag, _, rest = text.partition(" ")
        cmd = rest.split(" ", 1)[0].upper()
        log(re.sub(r"LOGIN .*", "LOGIN <redacted>", text, flags=re.I))
        if cmd == "CAPABILITY":
            out("* CAPABILITY IMAP4rev1")
            out(f"{tag} OK done")
        elif cmd == "LOGIN":
            if PASSWORD in rest:
                authed = True
                out(f"{tag} OK [CAPABILITY IMAP4rev1] logged in")
            else:
                out(f"{tag} NO [AUTHENTICATIONFAILED] invalid credentials")
        elif cmd == "LOGOUT":
            out("* BYE bye")
            out(f"{tag} OK done")
            return
        elif not authed:
            out(f"{tag} BAD not authenticated")
        elif cmd == "LIST":
            for l in LIST:
                out(l)
            out(f"{tag} OK done")
        elif cmd == "EXAMINE":
            name = rest.split(" ", 1)[1].strip('"')
            if name not in FOLDERS:
                out(f"{tag} NO no such folder")
                continue
            folder = name
            out(f"* {len(FOLDERS[name])} EXISTS")
            out("* OK [UIDVALIDITY 42] ok")
            out(f"{tag} OK [READ-ONLY] EXAMINE completed")
        elif cmd == "UID" and folder:
            if "BODY.PEEK[]" in rest:
                uids = {int(u) for u in rest.split(" ")[2].split(",")}
                for i, (uid, _, _, body) in enumerate(FOLDERS[folder], 1):
                    if uid in uids:
                        out(
                            f"* {i} FETCH (UID {uid} BODY[] {{{len(body)}}}".encode()
                            + b"\r\n"
                            + body
                            + b")\r\n"
                        )
            else:
                for i, (uid, flags, date, body) in enumerate(FOLDERS[folder], 1):
                    out(
                        f'* {i} FETCH (UID {uid} FLAGS ({flags}) INTERNALDATE "{date}" RFC822.SIZE {len(body)})'
                    )
            out(f"{tag} OK done")
        else:
            out(f"{tag} OK done")


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
srv = socket.create_server((BIND_HOST, PORT), reuse_port=False)
actual_port = srv.getsockname()[1]
if args.port_file:
    with open(args.port_file, "w") as pf:
        pf.write(f"{actual_port}\n")

while True:
    c, _ = srv.accept()
    try:
        c = ctx.wrap_socket(c, server_side=True)
    except ssl.SSLError:
        c.close()
        continue
    threading.Thread(target=lambda c=c: (serve(c), c.close()), daemon=True).start()
