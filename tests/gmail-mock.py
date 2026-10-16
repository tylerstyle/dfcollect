#!/usr/bin/env python3
"""A mock of Google OAuth 2.0 and the Gmail API for tests/gmail.nix:

- Service account JWT bearer flow (/token with grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer):
  verifies the RS256 signature against SA_PUB with `openssl dgst -sha256 -verify`
  and checks iss, sub, scope, aud, iat and exp;
- Installed app authorization-code + PKCE S256 flow (/o/oauth2/v2/auth -> 302 to
  http://127.0.0.1:<port>/?code=...&state=..., then /token with code_verifier,
  and refresh_token renewal);
- /gmail/v1/users/me/profile, /labels, /messages (two pages with
  includeSpamTrash=true), /messages/{id}?format=minimal and ?format=raw;
- one 429 with Retry-After on m2's raw fetch; m5's raw fetch revokes the first
  token (401) so the client must renew it.
"""
import base64, hashlib, json, ssl, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

PORT = int(sys.argv[1])
CERT, KEY, SA_PUB, REQUEST_LOG, BODIES = sys.argv[2:7]
BASE = f"https://server:{PORT}"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s):
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def jwt(claims):
    return b64url(b'{"alg":"none"}') + "." + b64url(json.dumps(claims).encode()) + ".sig"


lock = threading.Lock()
state = {
    "token_seq": 0,
    "valid_tokens": set(),
    "first_run_token": None,
    "revoked_once": False,
    "throttled_once": False,
    "pkce": {},  # code -> (challenge, redirect_uri)
}


def mint_token(sub, flow_tag):
    with lock:
        state["token_seq"] += 1
        n = state["token_seq"]
        tok = jwt({
            "sub": sub,
            "email": sub,
            "scope": GMAIL_SCOPE,
            "iss": "https://accounts.google.com",
            "aud": "dfcollect-test",
            "flow": flow_tag,
            "n": n,
        })
        state["valid_tokens"].add(tok)
        if state["first_run_token"] is None:
            state["first_run_token"] = tok
            state["revoked_once"] = False
            state["throttled_once"] = False
        return tok


def verify_sa_jwt(assertion):
    parts = assertion.split(".")
    assert len(parts) == 3, f"bad JWT structure: {assertion}"
    header = json.loads(b64url_decode(parts[0]))
    claims = json.loads(b64url_decode(parts[1]))
    sig = b64url_decode(parts[2])
    assert header.get("alg") == "RS256" and header.get("typ") == "JWT", header
    assert header.get("kid") == "kid-1", header
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    with tempfile.NamedTemporaryFile() as sf:
        sf.write(sig)
        sf.flush()
        res = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", SA_PUB, "-signature", sf.name],
            input=signing_input,
            capture_output=True,
        )
        if res.returncode != 0:
            raise ValueError(f"RS256 signature verification failed: {res.stderr.decode()}")
    assert claims.get("iss") == "dfcollect-sa@dfnix-test.iam.gserviceaccount.com", claims
    assert claims.get("sub") == "alice@workspace.test", claims
    assert claims.get("scope") == GMAIL_SCOPE, claims
    assert claims.get("aud") == f"{BASE}/token", claims
    iat = int(claims.get("iat", 0))
    exp = int(claims.get("exp", 0))
    assert exp - iat == 3600 and iat > 0, claims
    return claims["sub"]


def msg_bytes(n, subject):
    return (
        f"From: sender@example.org\r\nTo: alice@workspace.test\r\nSubject: {subject}\r\n"
        f"Message-ID: <{n}@workspace.test>\r\nMIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n\r\nGmail body {n} ({subject}) äöü\r\n"
    ).encode()


LABELS = [
    {"id": "INBOX", "name": "INBOX", "type": "system"},
    {"id": "SENT", "name": "SENT", "type": "system"},
    {"id": "DRAFT", "name": "DRAFT", "type": "system"},
    {"id": "SPAM", "name": "SPAM", "type": "system"},
    {"id": "TRASH", "name": "TRASH", "type": "system"},
    {"id": "UNREAD", "name": "UNREAD", "type": "system"},
    {"id": "Label_1", "name": "Projekte/Ärger", "type": "user"},
]

# id -> (labelIds, internalDate_ms_str, subject)
MESSAGES = {
    # Two labels (INBOX and Projekte/Ärger) -> stored once under INBOX
    "m1": (["Label_1", "INBOX"], "1772359200000", "m1 inbox+user"),       # 2026-03-01T10:00:00Z
    # User label with non-ASCII name + UNREAD -> stored under Projekte/Ärger
    "m2": (["Label_1", "UNREAD"], "1775030400000", "m2 user"),            # 2026-04-01T08:00:00Z
    # Before time window (2025-06-01T10:00:00Z) -> out of scope
    "m3": (["INBOX"], "1748772000000", "m3 old"),                         # 2025-06-01T10:00:00Z
    # Carries both INBOX and SPAM -> excluded by SPAM/**
    "m4": (["INBOX", "SPAM"], "1773568800000", "m4 spam"),                # 2026-03-15T10:00:00Z
    # SENT -> stored under SENT (triggers 401 token renewal)
    "m5": (["SENT"], "1774000800000", "m5 sent"),                         # 2026-03-20T10:00:00Z
    # TRASH -> stored under TRASH
    "m6": (["TRASH"], "1777716000000", "m6 trash"),                       # 2026-05-02T10:00:00Z
    # Only UNREAD -> stored under All Mail
    "m7": (["UNREAD"], "1778414400000", "m7 archived"),                   # 2026-05-10T12:00:00Z
}

bodies = {mid: msg_bytes(i, v[2]) for i, (mid, v) in enumerate(MESSAGES.items(), 1)}
with open(BODIES, "w") as f:
    json.dump({mid: base64.b64encode(b).decode() for mid, b in bodies.items()}, f)


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
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def record(self):
        auth = self.headers.get("Authorization", "")
        with lock, open(REQUEST_LOG, "a") as f:
            f.write(
                json.dumps({
                    "method": self.command,
                    "path": self.path,
                    "token": auth[7:][-8:] if auth.startswith("Bearer ") else "",
                })
                + "\n"
            )

    def do_POST(self):
        self.record()
        length = int(self.headers.get("Content-Length", 0))
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        path = urlsplit(self.path).path
        if path == "/token":
            g = form.get("grant_type")
            if g == "urn:ietf:params:oauth:grant-type:jwt-bearer":
                try:
                    sub = verify_sa_jwt(form.get("assertion", ""))
                except Exception as e:
                    return self.send(400, {"error": "invalid_grant", "error_description": str(e)})
                tok = mint_token(sub, "sa")
                return self.send(200, {
                    "access_token": tok,
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": GMAIL_SCOPE,
                })
            if g == "authorization_code":
                if form.get("client_id") != "desktop-client" or form.get("client_secret") != "desktop-secret":
                    return self.send(401, {"error": "invalid_client", "error_description": "bad client credentials"})
                code = form.get("code", "")
                with lock:
                    expected = state["pkce"].pop(code, None)
                if not expected:
                    return self.send(400, {"error": "invalid_grant", "error_description": "unknown code"})
                challenge, redir = expected
                verifier = form.get("code_verifier", "")
                got_challenge = b64url(hashlib.sha256(verifier.encode()).digest())
                if got_challenge != challenge or form.get("redirect_uri") != redir:
                    return self.send(400, {"error": "invalid_grant", "error_description": "PKCE or redirect_uri mismatch"})
                tok = mint_token("alice@workspace.test", "installed")
                return self.send(200, {
                    "access_token": tok,
                    "refresh_token": "rt-installed-1",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": GMAIL_SCOPE,
                })
            if g == "refresh_token":
                if (
                    form.get("client_id") == "desktop-client"
                    and form.get("client_secret") == "desktop-secret"
                    and form.get("refresh_token") == "rt-installed-1"
                ):
                    tok = mint_token("alice@workspace.test", "installed-refresh")
                    return self.send(200, {
                        "access_token": tok,
                        "expires_in": 3600,
                        "token_type": "Bearer",
                        "scope": GMAIL_SCOPE,
                    })
                return self.send(400, {"error": "invalid_grant", "error_description": "bad refresh token"})
            return self.send(400, {"error": "unsupported_grant_type", "error_description": str(g)})
        self.send(404, {"error": {"code": 404, "message": path}})

    def do_GET(self):
        self.record()
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        if u.path == "/o/oauth2/v2/auth":
            assert q.get("response_type") == ["code"], q
            assert q.get("client_id") == ["desktop-client"], q
            assert q.get("scope") == [GMAIL_SCOPE], q
            assert q.get("code_challenge_method") == ["S256"], q
            redir = q["redirect_uri"][0]
            st = q["state"][0]
            challenge = q["code_challenge"][0]
            with lock:
                code = f"code-{len(state['pkce']) + 1}"
                state["pkce"][code] = (challenge, redir)
            loc = f"{redir}?{urlencode({'code': code, 'state': st})}"
            return self.send(302, b"", ctype="text/plain", headers=[("Location", loc)])

        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        with lock:
            valid = token in state["valid_tokens"]
        if not valid:
            return self.send(401, {"error": {"code": 401, "message": "Invalid Credentials"}})

        if u.path == "/gmail/v1/users/me/profile":
            with lock:
                state["revoked_once"] = False
                state["throttled_once"] = False
            return self.send(200, {
                "emailAddress": "alice@workspace.test",
                "messagesTotal": len(MESSAGES),
                "threadsTotal": len(MESSAGES),
                "historyId": "9001",
            })
        if u.path == "/gmail/v1/users/me/labels":
            return self.send(200, {"labels": LABELS})
        if u.path == "/gmail/v1/users/me/messages":
            assert q.get("includeSpamTrash") == ["true"], q
            assert q.get("q") == ["after:1769817600 before:1780358400"], q
            # m8-vanished is listed here but disappears before its format=minimal fetch (404)
            all_ids = list(MESSAGES.keys()) + ["m8-vanished"]
            if "pageToken" not in q:
                return self.send(200, {
                    "messages": [{"id": mid, "threadId": f"t-{mid}"} for mid in all_ids[:4]],
                    "nextPageToken": "page-2",
                })
            assert q.get("pageToken") == ["page-2"], q
            return self.send(200, {
                "messages": [{"id": mid, "threadId": f"t-{mid}"} for mid in all_ids[4:]],
            })
        if u.path.startswith("/gmail/v1/users/me/messages/"):
            mid = unquote(u.path.rsplit("/", 1)[1])
            if mid not in MESSAGES:
                return self.send(404, {"error": {"code": 404, "message": f"Requested entity was not found: {mid}"}})
            label_ids, internal_date, _ = MESSAGES[mid]
            fmt = q.get("format", ["full"])[0]
            if fmt == "minimal":
                return self.send(200, {
                    "id": mid,
                    "threadId": f"t-{mid}",
                    "labelIds": label_ids,
                    "internalDate": internal_date,
                    "sizeEstimate": len(bodies[mid]),
                    "historyId": f"h-{mid}",
                })
            if fmt == "raw":
                with lock:
                    if mid == "m2" and not state["throttled_once"]:
                        state["throttled_once"] = True
                        return self.send(
                            429,
                            {"error": {"code": 429, "message": "Rate Limit Exceeded"}},
                            headers=[("Retry-After", "1")],
                        )
                    if mid == "m5" and not state["revoked_once"]:
                        state["revoked_once"] = True
                        state["valid_tokens"].discard(token)
                        return self.send(
                            401,
                            {"error": {"code": 401, "message": "Token revoked"}},
                        )
                return self.send(200, {
                    "id": mid,
                    "threadId": f"t-{mid}",
                    "labelIds": label_ids,
                    "internalDate": internal_date,
                    "sizeEstimate": len(bodies[mid]),
                    "historyId": f"h-{mid}",
                    "raw": b64url(bodies[mid]),
                })
        self.send(404, {"error": {"code": 404, "message": self.path}})


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
