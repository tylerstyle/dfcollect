# dfcollect graph against a mock of Microsoft Graph and the identity platform
# (tests/graph-mock.py), over TLS checked against the system CAs:
# - device-code sign-in (one pending poll), folders over two pages, a hidden
#   child folder with "/" in its name, a search folder (skipped), Recoverable
#   Items deletions; the scope takes a time window and excludes Junk Email,
#   whose messages are never listed;
# - a 429 is waited out, a revoked token renewed with the refresh token;
# - only GET requests reach Graph, all with immutable ids; the stored .eml
#   files are the served bytes;
# - a nextLink to another host never gets the token; a wrong client secret
#   aborts before anything is read.
#
#   nix-build tests/graph.nix          (dfcore from ../dfcore)
{ pkgs ? import <nixpkgs> { }
, dfcollect ? pkgs.callPackage ../package.nix { }
}:

let
  certs = pkgs.runCommand "dfcollect-graph-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out && cd $out
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=dfcollect-test-ca \
      -keyout ca-key.pem -out ca.pem 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj /CN=server -keyout key.pem -out server.csr 2>/dev/null
    printf 'basicConstraints=CA:FALSE\nsubjectAltName=DNS:server\nextendedKeyUsage=serverAuth\n' > ext
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 3650 \
      -extfile ext -out leaf.pem 2>/dev/null
    cat leaf.pem ca.pem > cert.pem
  '';
in
pkgs.testers.runNixOSTest {
  name = "dfcollect-graph";

  nodes.server = {
    networking.firewall.enable = false;
    systemd.services.graph-mock = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${./graph-mock.py} 8443 ${certs}/cert.pem ${certs}/key.pem /var/lib/requests.jsonl /var/lib/bodies.json";
    };
  };

  nodes.client = {
    networking.firewall.enable = false;
    security.pki.certificateFiles = [ "${certs}/ca.pem" ];
    environment.systemPackages = [ dfcollect pkgs.python3 pkgs.tmux ];
  };

  testScript = ''
    ${builtins.readFile ./tui.py}
    import base64, hashlib, json

    def run(out, *extra):
        return client.execute(
            f"dfcollect graph --graph-endpoint https://server:8443 --login-endpoint https://server:8443"
            f" --tenant tenant1 --client-id test-client -o {out} -C CASE-GRAPH -E mbx01 -e tester"
            " --exclude 'Junk Email/**' --not-before 2026-02-01T00:00:00Z --not-after 2026-06-01T00:00:00Z"
            " --json " + " ".join(extra)
        )

    def requests():
        return [json.loads(l) for l in server.succeed("cat /var/lib/requests.jsonl").splitlines()]

    start_all()
    server.wait_for_unit("graph-mock.service")
    server.wait_for_open_port(8443)
    client.wait_for_unit("multi-user.target")
    client.succeed("mkdir -p /target")
    bodies = json.loads(server.succeed("cat /var/lib/bodies.json"))

    with subtest("device code sign-in; only in-scope messages are fetched, byte for byte"):
        code, stdout = run("/target/dev")
        assert code == 0, (code, stdout)
        summary = json.loads(stdout)
        assert summary["messages"] == 5, summary
        items = [json.loads(l) for l in client.succeed("cat /target/dev/items.jsonl").splitlines()]
        got = {i["metadata"]["subject"]: i for i in items}
        assert sorted(got) == ["m1", "m2", "m4", "m6 sent", "m7 deleted"], sorted(got)
        for subject, item in got.items():
            want = hashlib.sha256(base64.b64decode(bodies[subject])).hexdigest()
            assert item["hashes"]["sha256"] == want, (subject, item)
            assert item["status"] == "acquired", item
        assert got["m4"]["path"].startswith("Inbox/Projekte%2F2026/20260501T100000Z-"), got["m4"]
        assert got["m7 deleted"]["path"].startswith("Recoverable Items/Deletions/"), got["m7 deleted"]
        assert got["m2"]["metadata"]["isRead"] is False and got["m1"]["metadata"]["isRead"] is True
        assert got["m2"]["account"] == "alice@contoso.test", got["m2"]
        assert got["m2"]["metadata"]["exchange_size"] > 1000, got["m2"]
        assert "@odata.etag" not in got["m2"]["metadata"], got["m2"]
        manifest = json.loads(client.succeed("cat /target/dev/manifest.json"))
        assert manifest["source"]["kind"] == "microsoft-graph", manifest["source"]
        ident = manifest["source"]["identity"]
        assert ident["user"]["userPrincipalName"] == "alice@contoso.test", ident
        assert ident["auth"]["method"] == "device code (delegated)", ident["auth"]
        assert ident["auth"]["claims"]["upn"] == "alice@contoso.test", ident["auth"]
        assert ident["tls"]["server:8443"]["verified_by"].startswith("system CA"), ident["tls"]
        counted = manifest["totals"]["unlisted_out_of_scope"]
        assert counted == {
            "receivedDateTime before the time window": 1,
            "folder excluded by Junk Email/**": 1,
        }, counted
        footprint = [json.loads(l) for l in client.succeed("cat /target/dev/footprint.jsonl").splitlines()]
        last = [f for f in footprint if f["kind"] == "disconnect"][0]["detail"]
        assert last["throttled_waits"] == 1 and last["token_renewals"] == 1, last
        client.succeed("dfcollect verify /target/dev")
        names = json.loads(client.succeed(
            "python3 -c \"import zipfile,json; print(json.dumps(zipfile.ZipFile('/target/dev/data.zip').namelist()))\""
        ))
        assert sorted(n for n in names if n.endswith(".eml")) == sorted(i["member"] for i in items), names
        # Graph saw only GETs (the POSTs went to the identity platform), all with immutable ids
        reqs = requests()
        graph = [r for r in reqs if r["path"].startswith("/v1.0/")]
        assert {r["method"] for r in graph} == {"GET"}, graph
        assert all(r["prefer"] == 'IdType="ImmutableId"' for r in graph), graph
        assert {r["path"].split("?")[0] for r in reqs if r["method"] == "POST"} == {
            "/tenant1/oauth2/v2.0/devicecode", "/tenant1/oauth2/v2.0/token"}, reqs
        assert not any("/mailFolders/junk/messages" in r["path"] for r in reqs), "Junk was listed"
        assert not any("/mailFolders/search/" in r["path"] for r in reqs), "a search folder was read"

    with subtest("a dry run signs in and counts what the run takes; no body is fetched"):
        before = len(requests())
        code, stdout = run("/target/dry", "--dry-run")
        assert code == 0, (code, stdout)
        pv = json.loads(stdout)
        assert pv["dry_run"] and pv["in_scope"] == 5, pv
        assert pv["account"] == "alice@contoso.test", pv
        assert pv["auth_method"] == "device code (delegated)", pv
        assert pv["out_of_scope"] == {
            "receivedDateTime before the time window": 1,
            "folder excluded by Junk Email/**": 1,
        }, pv
        new = requests()[before:]
        assert new and not any("/$value" in r["path"] for r in new), new
        assert {r["method"] for r in new if r["path"].startswith("/v1.0/")} == {"GET"}, new
        client.fail("test -e /target/dry")

    with subtest("TUI interactive run: single device-code sign-in shared between preview and run"):
        before = len(requests())
        tui = TuiDriver(client)
        tui.start()
        tui.wait_for_text("dfcollect")
        tui.send_keys("g")
        tui.wait_for_text("Microsoft 365 / Exchange Online via Graph")

        tui.fill_field("Case number", "CASE-GRAPH")
        tui.fill_field("Evidence number", "tui-graph01")
        tui.fill_field("Examiner", "tester")
        tui.fill_field("Tenant", "tenant1")
        tui.fill_field("App client ID", "test-client")
        tui.cycle_field("Cloud preset", "custom")
        tui.fill_field("Graph endpoint", "https://server:8443")
        tui.fill_field("Login endpoint", "https://server:8443")
        tui.fill_field("Output dir", "/target/tui-graph")

        # Start preview
        tui.send_keys("F2")
        tui.wait_for_text("Sign-In Required")
        # Polling against graph-mock auto-approves on 2nd poll
        tui.wait_for_text("Enter start", timeout=45)

        # Confirm acquisition start
        tui.send_keys("Enter")
        tui.wait_for_text("Confirm Acquisition Start")
        tui.send_keys("y")

        # Wait for acquisition result
        tui.wait_for_text("Acquisition Result", timeout=45)
        tui.wait_for_text("Status      : COMPLETE")
        tui.wait_for_text("q quit")
        tui.send_keys("q")
        tui.wait_for_exit()

        manifest = json.loads(client.succeed("cat /target/tui-graph/manifest.json"))
        assert manifest["status"] == "complete", manifest
        client.succeed("dfcollect verify /target/tui-graph")

        new_reqs = requests()[before:]
        device_code_reqs = [r for r in new_reqs if r["path"] == "/tenant1/oauth2/v2.0/devicecode"]
        assert len(device_code_reqs) == 1, f"Expected 1 device-code request, got {len(device_code_reqs)}: {device_code_reqs}"
        graph_reqs = [r for r in new_reqs if r["path"].startswith("/v1.0/")]
        assert len(graph_reqs) > 0, "No graph requests during TUI run"
        tokens = {r["token"] for r in graph_reqs if "token" in r and r["token"]}
        # at1 is used across preview and run until m6 triggers token renewal to at2
        assert len(tokens) <= 2 and all(tokens), f"Unexpected auth tokens: {tokens}"

    with subtest("a nextLink to another host never gets the token"):
        before = len(requests())
        code, stdout = run("/target/evil", "--auth app --mailbox mallory@contoso.test",
                           "--client-secret-file <(echo s3cret)")
        assert code == 6, (code, stdout)
        manifest = json.loads(client.succeed("cat /target/evil/manifest.json"))
        assert "refusing to send the token to https://evil.test" in " ".join(manifest["errors"]), manifest
        assert manifest["source"]["identity"]["auth"]["method"].startswith("client credentials"), manifest

    with subtest("a wrong client secret aborts before anything is read"):
        code, stdout = run("/target/badsecret", "--auth app --mailbox alice@contoso.test",
                           "--client-secret-file <(echo wrong)")
        assert code == 4, (code, stdout)
        manifest = json.loads(client.succeed("cat /target/badsecret/manifest.json"))
        assert "invalid_client" in " ".join(manifest["errors"]), manifest
        assert manifest["totals"]["acquired"] == 0, manifest

    with subtest("m365-logs: sign-ins, directory audits and the Unified Audit Log"):
        served = json.loads(server.succeed("cat /var/lib/logs.json"))
        before = len(requests())
        code, stdout = client.execute(
            "dfcollect m365-logs --graph-endpoint https://server:8443 --login-endpoint https://server:8443"
            " --tenant tenant1 --client-id test-client --auth app --client-secret-file <(echo s3cret)"
            " --not-before 2026-03-01T00:00:00Z --not-after 2026-04-01T00:00:00Z --user alice@contoso.test"
            " --ual-poll 1 -o /target/logs -C CASE-GRAPH -E logs01 -e tester --json"
        )
        assert code == 0, (code, stdout)
        items = {i["path"]: i for i in (json.loads(l) for l in client.succeed("cat /target/logs/items.jsonl").splitlines())}
        assert sorted(items) == ["logs/directory-audits", "logs/signins", "logs/unified-audit-log"], items
        for name, recs in served.items():
            item = items[f"logs/{name}"]
            assert item["status"] == "acquired" and item["metadata"]["records"] == len(recs), item
            stored = client.succeed(
                f"python3 -c \"import zipfile; print(zipfile.ZipFile('/target/logs/data.zip').read('logs/{name}.jsonl').decode())\""
            ).strip().splitlines()
            assert [json.loads(l)["id"] for l in stored] == [r["id"] for r in recs], (name, stored)
        assert items["logs/unified-audit-log"]["metadata"]["query_id"] == "q1", items["logs/unified-audit-log"]
        reqs = requests()[before:]
        posts = [r for r in reqs if r["method"] == "POST" and r["path"].startswith("/v1.0/")]
        assert len(posts) == 1 and posts[0]["path"] == "/v1.0/security/auditLog/queries", posts
        assert posts[0]["body"]["userPrincipalNameFilters"] == ["alice@contoso.test"], posts
        signin_gets = [r["path"] for r in reqs if "/auditLogs/signIns" in r["path"]]
        assert len(signin_gets) == 2 and "alice%40contoso.test" in signin_gets[0], signin_gets
        footprint = [json.loads(l) for l in client.succeed("cat /target/logs/footprint.jsonl").splitlines()]
        ual = [f["detail"] for f in footprint if f["kind"] == "audit_log_query"]
        assert ual[-1]["status"] == "succeeded" and ual[-1]["polls"] == 2, ual
        manifest = json.loads(client.succeed("cat /target/logs/manifest.json"))
        assert manifest["scope"]["accounts"] == ["alice@contoso.test"], manifest["scope"]
        client.succeed("dfcollect verify /target/logs")

    with subtest("m365-logs: a log the tenant refuses fails alone"):
        code, stdout = client.execute(
            "dfcollect m365-logs --graph-endpoint https://server:8443 --login-endpoint https://server:8443"
            " --tenant tenant1 --client-id test-client --auth app --client-secret-file <(echo s3cret)"
            " --not-before 2026-03-01T00:00:00Z --not-after 2026-04-01T00:00:00Z --user nopremium@contoso.test"
            " --logs signins,directory -o /target/logs2 -C CASE-GRAPH -E logs02 -e tester --json"
        )
        items = {i["path"]: i for i in (json.loads(l) for l in client.succeed("cat /target/logs2/items.jsonl").splitlines())}
        assert items["logs/signins"]["status"] == "error", items
        assert "NonPremium" in items["logs/signins"]["reason"], items
        assert items["logs/directory-audits"]["status"] == "acquired", items
        manifest = json.loads(client.succeed("cat /target/logs2/manifest.json"))
        assert manifest["status"] == "complete_with_errors", manifest

    with subtest("TUI interactive run: m365-logs (direct run, single device-code sign-in, verify)"):
        before = len(requests())
        tui = TuiDriver(client)
        tui.start()
        tui.wait_for_text("dfcollect")
        tui.send_keys("l")
        tui.wait_for_text("[M365 Logs]")

        tui.fill_field("Case number", "CASE-GRAPH")
        tui.fill_field("Evidence number", "tui-logs01")
        tui.fill_field("Examiner", "tester")
        tui.fill_field("Tenant", "tenant1")
        tui.fill_field("App client ID", "test-client")
        tui.cycle_field("Cloud preset", "custom")
        tui.fill_field("Graph endpoint", "https://server:8443")
        tui.fill_field("Login endpoint", "https://server:8443")
        tui.fill_field("Not before", "2026-03-01T00:00:00Z")
        tui.fill_field("Not after", "2026-04-01T00:00:00Z")
        tui.fill_field("Output dir", "/target/tui-logs")

        # Start acquisition directly (m365-logs has no preview step)
        tui.send_keys("F2")
        tui.wait_for_text("Confirm Acquisition Start")
        tui.send_keys("y")

        # Wait for acquisition result
        tui.wait_for_text("Acquisition Result", timeout=45)
        tui.wait_for_text("Status      : COMPLETE")
        tui.wait_for_text("q quit")
        tui.send_keys("q")
        tui.wait_for_exit()

        manifest = json.loads(client.succeed("cat /target/tui-logs/manifest.json"))
        assert manifest["status"] == "complete", manifest
        items = {i["path"]: i for i in (json.loads(l) for l in client.succeed("cat /target/tui-logs/items.jsonl").splitlines())}
        assert sorted(items) == ["logs/directory-audits", "logs/signins", "logs/unified-audit-log"], items
        assert all(i["status"] == "acquired" for i in items.values()), items
        client.succeed("dfcollect verify /target/tui-logs")

        new_reqs = requests()[before:]
        device_code_reqs = [r for r in new_reqs if r["path"] == "/tenant1/oauth2/v2.0/devicecode"]
        assert len(device_code_reqs) == 1, f"Expected 1 device-code request, got {len(device_code_reqs)}: {device_code_reqs}"
        graph_reqs = [r for r in new_reqs if r["path"].startswith("/v1.0/")]
        assert len(graph_reqs) > 0, "No graph requests during TUI m365-logs run"
  '';
}
