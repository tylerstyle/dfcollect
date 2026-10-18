# dfcollect imap against Dovecot: messages appended with known INTERNALDATEs
# and flags in INBOX, a folder with a non-ASCII name, Spam and Sent. The scope
# takes INBOX and Entwürfe within a time window and excludes Spam. Afterwards
# every flag on the server must be unchanged (EXAMINE, BODY.PEEK[]), the stored
# .eml files must be the appended bytes, and excluded folders never opened.
#
#   nix-build tests/imap.nix          (dfcore from ../dfcore)
{ pkgs ? import <nixpkgs> { }
, dfcollect ? pkgs.callPackage ../package.nix { }
}:

let
  # A test CA the client trusts, and a server certificate it signed
  certs = pkgs.runCommand "dfcollect-imap-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out && cd $out
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=dfcollect-test-ca \
      -keyout ca-key.pem -out ca.pem 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj /CN=server -keyout key.pem -out server.csr 2>/dev/null
    printf 'basicConstraints=CA:FALSE\nsubjectAltName=DNS:server\nextendedKeyUsage=serverAuth\n' > ext
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 3650 \
      -extfile ext -out leaf.pem 2>/dev/null
    cat leaf.pem ca.pem > cert.pem
    openssl x509 -in leaf.pem -outform DER | sha256sum | cut -d' ' -f1 > sha256
  '';

  populate = pkgs.writeScript "populate-mailbox" ''
    #!${pkgs.python3.interpreter}
    import hashlib, imaplib, json, sys

    def msg(n, subject):
        return (f"From: a@example.org\r\nTo: alice@example.org\r\nSubject: {subject}\r\n"
                f"Message-ID: <{n}@example.org>\r\n\r\nBody {n}\r\n").encode()

    # folder (modified UTF-7), flags, INTERNALDATE, subject
    plan = [
        ("INBOX", r"(\Seen)", '"01-Mar-2026 10:00:00 +0000"', "m1"),
        ("INBOX", "()", '"01-Apr-2026 10:00:00 +0200"', "m2"),
        ("INBOX", "()", '"01-Jun-2025 10:00:00 +0000"', "m3 old"),
        ("Entw&APw-rfe", r"(\Draft)", '"01-May-2026 10:00:00 +0000"', "m4"),
        ("Spam", "()", '"15-Mar-2026 10:00:00 +0000"', "m5 spam"),
        ("Sent", r"(\Seen)", '"20-Mar-2026 10:00:00 +0000"', "m6 sent"),
    ]
    expected = {}
    with imaplib.IMAP4("localhost") as imap:
        imap.login("alice", "foobar")
        for folder in ["Entw&APw-rfe", "Spam", "Sent"]:
            imap.create(folder)
        for i, (folder, flags, date, subject) in enumerate(plan, 1):
            data = msg(i, subject)
            typ, resp = imap.append(folder, flags, date, data)
            assert typ == "OK", resp
            expected[subject] = hashlib.sha256(data).hexdigest()
    json.dump(expected, sys.stdout)
  '';
in
pkgs.testers.runNixOSTest {
  name = "dfcollect-imap";

  nodes.server = { config, ... }: {
    imports = [ "${pkgs.path}/nixos/tests/common/user-account.nix" ];
    networking.firewall.enable = false;
    services.dovecot2 = {
      enable = true;
      enablePAM = true;
      settings = {
        dovecot_config_version = config.services.dovecot2.package.version;
        dovecot_storage_version = config.services.dovecot2.package.version;
        mail_driver = "maildir";
        mail_path = "~/Maildir";
        protocols = [ "imap" ];
        ssl = "yes";
        ssl_server_cert_file = "${certs}/cert.pem";
        ssl_server_key_file = "${certs}/key.pem";
      };
    };
    environment.systemPackages = [ config.services.dovecot2.package ];
  };

  nodes.client = {
    networking.firewall.enable = false;
    security.pki.certificateFiles = [ "${certs}/ca.pem" ];
    environment.systemPackages = [ dfcollect pkgs.python3 pkgs.tmux ];
  };

  testScript = ''
    ${builtins.readFile ./tui.py}
    import json

    def flags():
        return server.succeed("doveadm fetch -u alice 'mailbox uid flags' all | sort")

    def run(out, *extra):
        return client.execute(
            f"dfcollect imap server --user alice --password-file /root/pw -o {out}"
            " -C CASE-IMAP -E mail01 -e tester --include 'INBOX/**' --include 'Entwürfe/**'"
            " --exclude 'Spam/**' --not-before 2026-01-01T00:00:00Z --not-after 2026-07-01T00:00:00Z"
            " --json " + " ".join(extra)
        )

    start_all()
    server.wait_for_unit("dovecot.service")
    server.wait_for_open_port(993)
    expected = json.loads(server.succeed("${populate}"))
    before = flags()
    client.wait_for_unit("multi-user.target")
    client.succeed("printf 'foobar\\n' > /root/pw && mkdir -p /target")

    with subtest("TLS checked against the system CAs; only in-scope messages are fetched"):
        code, stdout = run("/target/tls")
        assert code == 0, (code, stdout)
        summary = json.loads(stdout)
        assert summary["messages"] == 3, summary
        tls_bytes = summary["bytes"]
        items = [json.loads(l) for l in client.succeed("cat /target/tls/items.jsonl").splitlines()]
        got = {i["path"]: i for i in items}
        assert sorted(got) == ["Entwürfe/1", "INBOX/1", "INBOX/2"], sorted(got)
        # \Recent is a session flag of IMAP4rev1 servers; only \Seen matters here
        assert "\\Seen" in got["INBOX/1"]["metadata"]["flags"], got["INBOX/1"]
        assert "\\Seen" not in got["INBOX/2"]["metadata"]["flags"], got["INBOX/2"]
        assert got["INBOX/2"]["times"]["modified"] == "2026-04-01T08:00:00.000000000Z", got["INBOX/2"]
        for path, subject in [("INBOX/1", "m1"), ("INBOX/2", "m2"), ("Entwürfe/1", "m4")]:
            assert got[path]["hashes"]["sha256"] == expected[subject], (path, got[path])
        footprint = [json.loads(l) for l in client.succeed("cat /target/tls/footprint.jsonl").splitlines()]
        commands = [f["detail"].get("command", "") for f in footprint if f["kind"] == "command"]
        assert 'EXAMINE "INBOX"' in commands, commands
        assert not any("Spam" in c or '"Sent"' in c for c in commands), commands
        manifest = json.loads(client.succeed("cat /target/tls/manifest.json"))
        assert manifest["source"]["identity"]["tls"]["verified_by"].startswith("system CA"), manifest
        counted = manifest["totals"]["unlisted_out_of_scope"]
        assert counted == {
            "INTERNALDATE before the time window": 1,
            "folder excluded by Spam/**": 1,
            "folder matches no include pattern": 1,
        }, counted
        client.succeed("dfcollect verify /target/tls")
        # The stored bytes are what was appended
        client.succeed(
            "python3 -c \"import zipfile,hashlib,sys; z=zipfile.ZipFile('/target/tls/data.zip');"
            " print(hashlib.sha256(z.read('INBOX/2.eml')).hexdigest())\" | grep -qx " + expected["m2"]
        )

    with subtest("STARTTLS with a pinned certificate"):
        pin = "${certs}/sha256"
        code, stdout = run("/target/starttls", "--security start-tls", f"--tls-sha256 $(cat {pin})")
        assert code == 0, (code, stdout)
        assert json.loads(stdout)["messages"] == 3

    with subtest("a wrong pin stops before login and the collection is aborted"):
        code, stdout = run("/target/wrongpin", "--tls-sha256 " + "0" * 64)
        assert code == 4, (code, stdout)
        manifest = json.loads(client.succeed("cat /target/wrongpin/manifest.json"))
        assert manifest["status"] == "aborted", manifest
        assert "pinned" in " ".join(manifest["errors"]), manifest

    with subtest("a dry run counts what the run takes, fetches no body and writes nothing"):
        code, stdout = run("/target/dry", "--dry-run")
        assert code == 0, (code, stdout)
        pv = json.loads(stdout)
        assert pv["dry_run"] and pv["in_scope"] == 3 and pv["bytes"] == tls_bytes, (pv, tls_bytes)
        assert pv["out_of_scope"] == {
            "INTERNALDATE before the time window": 1,
            "folder excluded by Spam/**": 1,
            "folder matches no include pattern": 1,
        }, pv
        assert pv["auth_method"] in ("PLAIN", "LOGIN"), pv
        client.fail("test -e /target/dry")

    with subtest("TUI interactive run: secret modal masks password and preview + run acquire cleanly"):
        tui = TuiDriver(client)
        tui.start()
        tui.wait_for_text("dfcollect")
        tui.send_keys("m")
        tui.wait_for_text("Mailboxes over IMAP")

        tui.fill_field("Case number", "CASE-IMAP")
        tui.fill_field("Evidence number", "tui-imap01")
        tui.fill_field("Examiner", "tester")
        tui.fill_field("IMAP server", "server:993")
        tui.fill_field("Account (user)", "alice")
        tui.fill_field("Output dir", "/target/tui-imap")

        # Start preview with F2
        tui.send_keys("F2")
        tui.wait_for_text("Credential Required")

        # Type password while modal is displayed
        tui.type_string("foobar")
        scr = tui.capture()
        assert "foobar" not in scr, "password leaked to screen"
        assert "••••••" in scr, "password bullets missing"
        hist = tui.capture(full_history=True)
        assert "foobar" not in hist, "password leaked to tmux history"

        # Submit password and wait for preview to finish and be ready
        tui.send_keys("Enter")
        tui.wait_for_text("Enter start")

        # Request acquisition start
        tui.send_keys("Enter")
        tui.wait_for_text("Confirm Acquisition Start")
        tui.send_keys("y")

        # Wait for acquisition result
        tui.wait_for_text("Acquisition Result")
        tui.wait_for_text("Status      : COMPLETE")
        tui.wait_for_text("q quit")
        assert "foobar" not in tui.capture(full_history=True), "password leaked during run"

        tui.send_keys("q")
        tui.wait_for_exit()

        manifest = json.loads(client.succeed("cat /target/tui-imap/manifest.json"))
        assert manifest["status"] == "complete", manifest
        client.succeed("dfcollect verify /target/tui-imap")
        tui_items = [json.loads(l) for l in client.succeed("cat /target/tui-imap/items.jsonl").splitlines()]
        assert len(tui_items) > 0, "No items acquired in TUI run"

    with subtest("no flag changed on the server"):
        assert flags() == before, (before, flags())
  '';
}
