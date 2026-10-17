# dfcollect gmail against a mock of Google OAuth 2.0 and the Gmail API
# (tests/gmail-mock.py), over TLS checked against the system CAs:
# - service-account sign-in (RS256 JWT assertion verified with openssl against
#   the test public key, plus claims iss/sub/scope/aud/iat/exp);
# - installed-app sign-in with PKCE (S256), both via the 127.0.0.1 loopback
#   listener (curl -L) and via pasting the redirect URL on stdin;
# - labels: INBOX, SENT, SPAM, TRASH, All Mail and a user label with a
#   non-ASCII name ("Projekte/Ärger"); a message with two labels stored once
#   under the priority label (INBOX);
# - scope: --exclude 'SPAM/**' plus an internalDate time window; out-of-scope
#   messages never have ?format=raw requested;
# - a 429 is waited out, a revoked token renewed (new JWT for service-account,
#   refresh_token for installed); only GET requests reach the Gmail API;
# - a token endpoint refusal aborts cleanly with exit code 4;
# - dfcollect verify passes on all collections.
#
#   nix-build tests/gmail.nix          (dfcore from ../dfcore)
{ pkgs ? import <nixpkgs> { }
, dfcollect ? pkgs.callPackage ../package.nix { }
}:

let
  certs = pkgs.runCommand "dfcollect-gmail-certs" { nativeBuildInputs = [ pkgs.openssl pkgs.python3 ]; } ''
    mkdir $out && cd $out
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=dfcollect-test-ca \
      -keyout ca-key.pem -out ca.pem 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj /CN=server -keyout key.pem -out server.csr 2>/dev/null
    printf 'basicConstraints=CA:FALSE\nsubjectAltName=DNS:server\nextendedKeyUsage=serverAuth\n' > ext
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 3650 \
      -extfile ext -out leaf.pem 2>/dev/null
    cat leaf.pem ca.pem > cert.pem

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out sa-key.pem 2>/dev/null
    openssl rsa -in sa-key.pem -pubout -out sa-pub.pem 2>/dev/null
    python3 - <<'PY'
    import json
    with open("sa-key.pem") as f:
        priv = f.read()
    with open("sa.json", "w") as f:
        json.dump({
            "type": "service_account",
            "project_id": "dfnix-test",
            "private_key_id": "kid-1",
            "private_key": priv,
            "client_email": "dfcollect-sa@dfnix-test.iam.gserviceaccount.com",
        }, f)
    with open("sa-bad.json", "w") as f:
        json.dump({
            "type": "service_account",
            "project_id": "dfnix-test",
            "private_key_id": "kid-1",
            "private_key": priv,
            "client_email": "wrong-sa@dfnix-test.iam.gserviceaccount.com",
        }, f)
    PY
  '';
in
pkgs.testers.runNixOSTest {
  name = "dfcollect-gmail";

  nodes.server = {
    networking.firewall.enable = false;
    systemd.services.gmail-mock = {
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.openssl ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${./gmail-mock.py} 8443 ${certs}/cert.pem ${certs}/key.pem ${certs}/sa-pub.pem /var/lib/requests.jsonl /var/lib/bodies.json";
    };
  };

  nodes.client = {
    networking.firewall.enable = false;
    security.pki.certificateFiles = [ "${certs}/ca.pem" ];
    environment.systemPackages = [ dfcollect pkgs.python3 pkgs.curl ];
  };

  testScript = ''
    import base64, hashlib, json

    COMMON_ARGS = (
        "--gmail-endpoint https://server:8443"
        " --token-endpoint https://server:8443/token"
        " --auth-endpoint https://server:8443/o/oauth2/v2/auth"
        " -C CASE-GMAIL -E gmail01 -e tester"
        " --exclude 'SPAM/**' --not-before 2026-02-01T00:00:00Z --not-after 2026-06-01T00:00:00Z"
        " --json"
    )

    def requests():
        return [json.loads(l) for l in server.succeed("cat /var/lib/requests.jsonl").splitlines()]

    def check_collection(dir_path, bodies, want_method):
        items = [json.loads(l) for l in client.succeed(f"cat {dir_path}/items.jsonl").splitlines()]
        got = {i["metadata"]["id"]: i for i in items}
        assert sorted(got) == ["m1", "m2", "m5", "m6", "m7", "m8-vanished"], sorted(got)
        vanished = got.pop("m8-vanished")
        assert vanished["status"] == "error", vanished
        assert "GET format=minimal: HTTP 404:" in vanished["reason"], vanished
        assert "Requested entity was not found: m8-vanished" in vanished["reason"], vanished
        for mid, item in got.items():
            want = hashlib.sha256(base64.b64decode(bodies[mid])).hexdigest()
            assert item["hashes"]["sha256"] == want, (mid, item)
            assert item["status"] == "acquired", item
            assert item["account"] == "alice@workspace.test", item
        # m1 carries ["Label_1", "INBOX"] -> stored once under INBOX
        assert got["m1"]["path"] == "INBOX/20260301T100000Z-m1", got["m1"]
        assert got["m1"]["metadata"]["labelNames"] == ["Projekte/Ärger", "INBOX"], got["m1"]
        # m2 carries ["Label_1", "UNREAD"] -> stored under non-ASCII user label "Projekte/Ärger"
        assert got["m2"]["path"] == "Projekte/Ärger/20260401T080000Z-m2", got["m2"]
        # m5 -> SENT, m6 -> TRASH, m7 (only UNREAD) -> All Mail
        assert got["m5"]["path"] == "SENT/20260320T100000Z-m5", got["m5"]
        assert got["m6"]["path"] == "TRASH/20260502T100000Z-m6", got["m6"]
        assert got["m7"]["path"] == "All Mail/20260510T120000Z-m7", got["m7"]

        manifest = json.loads(client.succeed(f"cat {dir_path}/manifest.json"))
        assert manifest["source"]["kind"] == "gmail", manifest["source"]
        assert manifest["totals"]["errors"] == 1, manifest["totals"]
        ident = manifest["source"]["identity"]
        assert ident["profile"]["emailAddress"] == "alice@workspace.test", ident
        assert ident["auth"]["method"] == want_method, ident["auth"]
        assert ident["tls"]["server:8443"]["verified_by"].startswith("system CA"), ident["tls"]
        counted = manifest["totals"]["unlisted_out_of_scope"]
        assert counted == {
            "internalDate before the time window": 1,
            "excluded by SPAM/**": 1,
        }, counted
        footprint = [json.loads(l) for l in client.succeed(f"cat {dir_path}/footprint.jsonl").splitlines()]
        list_fp = [
            f["detail"]
            for f in footprint
            if f["kind"] == "request"
            and f["detail"].get("request") == "GET users/me/messages?includeSpamTrash=true"
        ][0]
        assert list_fp["q"] == "after:1769817600 before:1780358400", list_fp
        last = [f for f in footprint if f["kind"] == "disconnect"][0]["detail"]
        assert last["throttled_waits"] == 1 and last["token_renewals"] == 1, last
        client.succeed(f"dfcollect verify {dir_path}")
        names = json.loads(client.succeed(
            f"python3 -c \"import zipfile,json; print(json.dumps(zipfile.ZipFile('{dir_path}/data.zip').namelist()))\""
        ))
        assert sorted(n for n in names if n.endswith(".eml")) == sorted(i["member"] for i in got.values()), names

    start_all()
    server.wait_for_unit("gmail-mock.service")
    server.wait_for_open_port(8443)
    client.wait_for_unit("multi-user.target")
    client.succeed("mkdir -p /target && printf 'desktop-secret\\n' > /target/client-secret")
    bodies = json.loads(server.succeed("cat /var/lib/bodies.json"))

    with subtest("service-account sign-in (RS256 JWT), labels, scope, 404 mid-run, 429, renewal and verify"):
        code, stdout = client.execute(
            f"dfcollect gmail --auth service-account --key-file ${certs}/sa.json"
            f" --mailbox alice@workspace.test -o /target/sa {COMMON_ARGS}"
        )
        assert code == 7, (code, stdout)
        summary = json.loads(stdout)
        assert summary["messages"] == 5 and summary["errors"] == 1, summary
        check_collection("/target/sa", bodies, "service account (domain-wide delegation)")

        reqs = requests()
        gmail_reqs = [r for r in reqs if r["path"].startswith("/gmail/v1/")]
        assert {r["method"] for r in gmail_reqs} == {"GET"}, gmail_reqs
        assert not any("messages/m3?format=raw" in r["path"] for r in gmail_reqs), "out-of-scope m3 fetched raw"
        assert not any("messages/m4?format=raw" in r["path"] for r in gmail_reqs), "excluded m4 fetched raw"

    with subtest("a dry run counts what the run takes and fetches no message body"):
        before = len(requests())
        code, stdout = client.execute(
            f"dfcollect gmail --auth service-account --key-file ${certs}/sa.json"
            f" --mailbox alice@workspace.test -o /target/dry --dry-run {COMMON_ARGS}"
        )
        assert code == 0, (code, stdout)
        pv = json.loads(stdout)
        assert pv["in_scope"] == 5 and pv["errors"] == 1 and pv["bytes"] > 0, pv
        assert pv["out_of_scope"] == {
            "internalDate before the time window": 1,
            "excluded by SPAM/**": 1,
        }, pv
        assert pv["auth_method"] == "service account (domain-wide delegation)", pv
        new = requests()[before:]
        assert new and not any("format=raw" in r["path"] for r in new), new
        client.fail("test -e /target/dry")

    with subtest("installed sign-in via loopback listener (ignores probes without state, then curl -L)"):
        client.succeed(
            f"python3 - <<'PY'\n"
            f"import json, subprocess\n"
            f"from urllib.parse import parse_qs, urlsplit\n"
            f'cmd = "dfcollect gmail --auth installed --client-id desktop-client --client-secret-file /target/client-secret -o /target/inst-loop {COMMON_ARGS}"\n'
            f"p = subprocess.Popen(cmd, shell=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)\n"
            f"auth_url = None\n"
            f"for line in p.stderr:\n"
            f"    if line.startswith('https://server:8443/o/oauth2/v2/auth?'):\n"
            f"        auth_url = line.strip()\n"
            f"        break\n"
            f"assert auth_url, 'did not see auth URL on stderr'\n"
            f"redir = parse_qs(urlsplit(auth_url).query)['redirect_uri'][0]\n"
            f"probe = subprocess.check_output(['curl', '-sS', '-o', '/dev/null', '-w', '%{{http_code}}', redir + '/favicon.ico'], text=True)\n"
            f"assert probe == '404', probe\n"
            f"subprocess.run(['curl', '-sS', '-L', auth_url], check=True)\n"
            f"out, err = p.communicate(timeout=60)\n"
            f"assert p.returncode == 7, (p.returncode, out, err)\n"
            f"summary = json.loads(out)\n"
            f"assert summary['messages'] == 5 and summary['errors'] == 1, summary\n"
            f"PY"
        )
        check_collection(
            "/target/inst-loop",
            bodies,
            "installed application (OAuth 2.0 authorization code with PKCE)",
        )

    with subtest("installed sign-in via redirect URL pasted on stdin"):
        client.succeed(
            f"python3 - <<'PY'\n"
            f"import json, subprocess\n"
            f'cmd = "dfcollect gmail --auth installed --client-id desktop-client --client-secret-file /target/client-secret -o /target/inst-paste {COMMON_ARGS}"\n'
            f"p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)\n"
            f"auth_url = None\n"
            f"for line in p.stderr:\n"
            f"    if line.startswith('https://server:8443/o/oauth2/v2/auth?'):\n"
            f"        auth_url = line.strip()\n"
            f"        break\n"
            f"assert auth_url, 'did not see auth URL on stderr'\n"
            f"# Fetch only the 302 Location header from the auth server without connecting to 127.0.0.1\n"
            f"hdrs = subprocess.check_output(['curl', '-sS', '-D', '-', '-o', '/dev/null', auth_url], text=True)\n"
            f"loc = [l.split(':', 1)[1].strip() for l in hdrs.splitlines() if l.lower().startswith('location:')][0]\n"
            f"assert loc.startswith('http://127.0.0.1:'), loc\n"
            f"out, err = p.communicate(input=loc + '\\n', timeout=60)\n"
            f"assert p.returncode == 7, (p.returncode, out, err)\n"
            f"summary = json.loads(out)\n"
            f"assert summary['messages'] == 5 and summary['errors'] == 1, summary\n"
            f"PY"
        )
        check_collection(
            "/target/inst-paste",
            bodies,
            "installed application (OAuth 2.0 authorization code with PKCE)",
        )

    with subtest("token endpoint error aborts cleanly with exit code 4"):
        code, stdout = client.execute(
            f"dfcollect gmail --auth service-account --key-file ${certs}/sa-bad.json"
            f" --mailbox alice@workspace.test -o /target/bad-sa {COMMON_ARGS}"
        )
        assert code == 4, (code, stdout)
        manifest = json.loads(client.succeed("cat /target/bad-sa/manifest.json"))
        assert "invalid_grant" in " ".join(manifest["errors"]), manifest
        assert manifest["totals"]["acquired"] == 0, manifest
  '';
}
