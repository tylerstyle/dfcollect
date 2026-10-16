#!/usr/bin/env python3
"""A mock of the Microsoft identity platform and Microsoft Graph mail API for
tests/graph.nix. It logs every request (method, path, token) to REQUEST_LOG
and serves:

- device code sign-in for tenant1 (one authorization_pending, then a token
  with a refresh token), refresh, and client credentials (secret "s3cret");
- /v1.0/me and /v1.0/users/{mailbox}: folders over two pages (a search
  folder among them), a hidden child folder whose name contains "/",
  Recoverable Items deletions, messages with metadata, and $value bodies;
- one 429 with Retry-After for m2's body; m6's body revokes the first
  access token (401), so the client must renew it;
- for mallory@contoso.test, a nextLink to another host.
"""
import base64, json, ssl, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

PORT = int(sys.argv[1])
CERT, KEY, REQUEST_LOG, BODIES = sys.argv[2:6]
BASE = f"https://server:{PORT}"

def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def jwt(claims):
    return b64url(b'{"alg":"none"}') + "." + b64url(json.dumps(claims).encode()) + ".sig"

TOKENS = {
    "at1": jwt({"tid": "tenant1", "upn": "alice@contoso.test", "scp": "Mail.Read", "app_displayname": "dfnix test", "n": 1}),
    "at2": jwt({"tid": "tenant1", "upn": "alice@contoso.test", "scp": "Mail.Read", "app_displayname": "dfnix test", "n": 2}),
    "app": jwt({"tid": "tenant1", "roles": ["Mail.Read"], "app_displayname": "dfnix test", "n": 3}),
}
VALID = {TOKENS["at1"], TOKENS["at2"], TOKENS["app"]}
lock = threading.Lock()
state = {"polls": 0, "throttled": False}

def msg(n, subject):
    return (f"From: a@example.org\r\nTo: alice@contoso.test\r\nSubject: {subject}\r\n"
            f"Message-ID: <{n}@example.org>\r\nMIME-Version: 1.0\r\n\r\nBody {n} ä\r\n").encode()

# folder id -> (display name, parent, hidden, total)
FOLDERS = {
    "inbox": ("Inbox", None, False, 3),
    "proj": ("Projekte/2026", "inbox", True, 1),
    "junk": ("Junk Email", None, False, 1),
    "sent": ("Sent Items", None, False, 1),
    "search": ("Ungelesen", None, False, 2),
}
# message id -> (folder, received, subject, isRead)
MESSAGES = {
    "m1": ("inbox", "2026-03-01T10:00:00Z", "m1", True),
    "m2": ("inbox", "2026-04-01T08:00:00Z", "m2", False),
    "m3": ("inbox", "2025-06-01T10:00:00Z", "m3 old", True),
    "m4": ("proj", "2026-05-01T10:00:00Z", "m4", False),
    "m5": ("junk", "2026-03-15T10:00:00Z", "m5 junk", False),
    "m6": ("sent", "2026-03-20T10:00:00Z", "m6 sent", True),
    "m7": ("rid", "2026-05-02T10:00:00Z", "m7 deleted", True),
}
bodies = {k: msg(i, v[2]) for i, (k, v) in enumerate(MESSAGES.items(), 1)}
with open(BODIES, "w") as f:
    json.dump({v[2]: base64.b64encode(bodies[k]).decode() for k, v in MESSAGES.items()}, f)

def folder_json(fid):
    name, parent, hidden, total = FOLDERS[fid]
    children = sum(1 for v in FOLDERS.values() if v[1] == fid)
    f = {"id": fid, "displayName": name, "parentFolderId": parent or "root",
         "childFolderCount": children, "totalItemCount": total, "unreadItemCount": 0, "isHidden": hidden}
    if fid == "search":
        f["@odata.type"] = "#microsoft.graph.mailSearchFolder"
    return f

def message_json(mid):
    folder, received, subject, read = MESSAGES[mid]
    return {"@odata.etag": "W/\"x\"", "id": mid, "internetMessageId": f"<{mid}@example.org>",
            "receivedDateTime": received, "sentDateTime": received, "createdDateTime": received,
            "lastModifiedDateTime": received, "subject": subject, "isRead": read, "isDraft": False,
            "parentFolderId": folder,
            "singleValueExtendedProperties": [{"id": "Integer 0xe08", "value": str(len(bodies[mid]) + 1000)}]}

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json", headers=()):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        if code == 200 and ctype != "application/json":
            # bodies chunked, to exercise the client's decoder
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(data), 7):
                part = data[i:i + 7]
                self.wfile.write(b"%x\r\n" % len(part) + part + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            return
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def record(self):
        auth = self.headers.get("Authorization", "")
        with lock, open(REQUEST_LOG, "a") as f:
            f.write(json.dumps({"method": self.command, "path": self.path, "token": auth[7:][-8:],
                                "prefer": self.headers.get("Prefer")}) + "\n")

    def do_POST(self):
        self.record()
        length = int(self.headers.get("Content-Length", 0))
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        path = urlsplit(self.path).path
        if path == "/tenant1/oauth2/v2.0/devicecode":
            assert "Mail.Read" in form["scope"] and "offline_access" in form["scope"], form
            return self.send(200, {"device_code": "dc1", "user_code": "ABCD-EFGH", "interval": 1,
                                   "verification_uri": "https://microsoft.com/devicelogin", "expires_in": 900,
                                   "message": "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code ABCD-EFGH to authenticate."})
        if path == "/tenant1/oauth2/v2.0/token":
            g = form.get("grant_type")
            if g == "urn:ietf:params:oauth:grant-type:device_code":
                with lock:
                    state["polls"] += 1
                    if state["polls"] == 1:
                        return self.send(400, {"error": "authorization_pending", "error_description": "AADSTS70016: pending"})
                return self.send(200, {"access_token": TOKENS["at1"], "refresh_token": "rt1", "expires_in": 3600,
                                       "token_type": "Bearer", "scope": form.get("scope", f"{BASE}/Mail.Read")})
            if g == "refresh_token" and form.get("refresh_token") == "rt1":
                return self.send(200, {"access_token": TOKENS["at2"], "refresh_token": "rt2", "expires_in": 3600, "token_type": "Bearer"})
            if g == "client_credentials" and form.get("client_secret") == "s3cret":
                return self.send(200, {"access_token": TOKENS["app"], "expires_in": 3600, "token_type": "Bearer"})
            return self.send(401, {"error": "invalid_client", "error_description": "AADSTS7000215: bad secret"})
        self.send(404, {"error": {"code": "NotFound", "message": path}})

    def do_GET(self):
        self.record()
        token = self.headers.get("Authorization", "")[7:]
        with lock:
            valid = token in VALID
        if not valid:
            return self.send(401, {"error": {"code": "InvalidAuthenticationToken", "message": "expired"}})
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        parts = [unquote(p) for p in u.path.split("/")[2:]]  # after /v1.0
        if parts[0] == "users":
            who = parts[1]
            parts = parts[2:]
        else:
            who = parts[0]
            parts = parts[1:]
        if who not in ("me", "alice@contoso.test", "mallory@contoso.test"):
            return self.send(404, {"error": {"code": "ErrorInvalidUser", "message": who}})
        if parts == []:
            upn = "mallory@contoso.test" if who.startswith("mallory") else "alice@contoso.test"
            return self.send(200, {"id": "u1", "displayName": "Alice", "userPrincipalName": upn, "mail": upn})
        if parts == ["mailFolders"]:
            assert q.get("includeHiddenFolders") == ["true"], q
            if who.startswith("mallory"):
                return self.send(200, {"value": [], "@odata.nextLink": "https://evil.test/v1.0/steal"})
            top = [f for f in FOLDERS if FOLDERS[f][1] is None]
            if "$skip" not in q:
                return self.send(200, {"value": [folder_json(f) for f in top[:2]],
                                       "@odata.nextLink": f"{BASE}{u.path}?includeHiddenFolders=true&$top=100&$skip=2"})
            return self.send(200, {"value": [folder_json(f) for f in top[2:]]})
        if parts == ["mailFolders", "recoverableitemsdeletions"]:
            return self.send(200, {"id": "rid", "displayName": "Deletions", "totalItemCount": 1, "childFolderCount": 0})
        if len(parts) == 3 and parts[0] == "mailFolders" and parts[2] == "childFolders":
            return self.send(200, {"value": [folder_json(f) for f in FOLDERS if FOLDERS[f][1] == parts[1]]})
        if len(parts) == 3 and parts[0] == "mailFolders" and parts[2] == "messages":
            assert "singleValueExtendedProperties" in q.get("$expand", [""])[0], q
            ids = [m for m, v in MESSAGES.items() if v[0] == parts[1]]
            return self.send(200, {"value": [message_json(m) for m in ids]})
        if len(parts) == 3 and parts[0] == "messages" and parts[2] == "$value":
            mid = parts[1]
            with lock:
                if mid == "m2" and not state["throttled"]:
                    state["throttled"] = True
                    return self.send(429, {"error": {"code": "ApplicationThrottled", "message": "slow down"}}, headers=[("Retry-After", "1")])
                if mid == "m6" and TOKENS["at1"] in VALID:
                    VALID.discard(TOKENS["at1"])
                    return self.send(401, {"error": {"code": "InvalidAuthenticationToken", "message": "revoked"}})
            return self.send(200, bodies[mid], ctype="text/plain")
        self.send(404, {"error": {"code": "NotFound", "message": self.path}})

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
