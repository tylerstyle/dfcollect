# dfcollect db against PostgreSQL and MariaDB servers: a dump per database,
# streamed into the container, restorable with the engine's own tools; the
# server's version and time zone recorded; the password in no record and its
# temporary file gone afterwards.
#
#   nix-build tests/db.nix          (dfcore from ../dfcore)
{ pkgs ? import <nixpkgs> { }
, dfcollect ? pkgs.callPackage ../package.nix { }
}:

pkgs.testers.runNixOSTest {
  name = "dfcollect-db";

  nodes.server = {
    networking.firewall.allowedTCPPorts = [ 5432 3306 ];
    services.postgresql = {
      enable = true;
      enableTCPIP = true;
      authentication = ''
        host all all 0.0.0.0/0 scram-sha-256
        host all all ::/0 scram-sha-256
      '';
    };
    services.mysql = {
      enable = true;
      package = pkgs.mariadb;
      settings.mysqld.bind-address = "0.0.0.0";
    };
  };

  nodes.client = {
    environment.systemPackages = [ dfcollect pkgs.postgresql pkgs.mariadb.client pkgs.python3 pkgs.tmux ];
  };

  testScript = ''
    ${builtins.readFile ./tui.py}
    import json

    start_all()
    server.wait_for_unit("postgresql.service")
    server.wait_for_unit("mysql.service")
    server.succeed(
        "sudo -u postgres psql -v ON_ERROR_STOP=1 -c \"CREATE ROLE examiner LOGIN PASSWORD 'pg-pass-123'\""
        " -c 'CREATE DATABASE shop'"
    )
    server.succeed(
        "sudo -u postgres psql -v ON_ERROR_STOP=1 -d shop"
        " -c 'CREATE TABLE items (id int primary key, name text)'"
        " -c \"INSERT INTO items VALUES (1, 'alpha'), (2, 'beta')\""
        " -c 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO examiner'"
    )
    server.succeed(
        "mariadb -e \"CREATE DATABASE shop; CREATE TABLE shop.items (id int primary key, name varchar(20)) ENGINE=InnoDB;"
        " INSERT INTO shop.items VALUES (1, 'alpha'), (2, 'beta');"
        " CREATE USER 'examiner'@'%' IDENTIFIED BY 'my-pass-123';"
        " GRANT SELECT, SHOW VIEW, TRIGGER, EVENT, PROCESS ON *.* TO 'examiner'@'%';\""
    )
    client.wait_for_unit("multi-user.target")
    client.succeed("mkdir -p /target && printf 'pg-pass-123\\n' > /root/pgpw && printf 'my-pass-123\\n' > /root/mypw")
    client.wait_until_succeeds("PGPASSWORD=pg-pass-123 psql -h server -U examiner -d postgres -c 'select 1'")

    def member(out, name):
        return client.succeed(
            f"python3 -c \"import zipfile,sys; sys.stdout.buffer.write(zipfile.ZipFile('{out}/data.zip').read('{name}'))\" > /tmp/m && echo /tmp/m"
        ).strip()

    with subtest("PostgreSQL: a dry run lists the databases with sizes and dumps nothing"):
        code, stdout = client.execute(
            "dfcollect db postgres --host server --user examiner --password-file /root/pgpw --tls off"
            " -o /target/pgd -C CASE-DB -E db00 -e tester --dry-run --json"
        )
        assert code == 0, (code, stdout)
        pv = json.loads(stdout)
        dbs = {d["name"]: d for d in pv["databases"]}
        assert {"postgres", "shop"} <= set(dbs), pv
        assert dbs["shop"]["bytes"] > 0 and dbs["shop"]["in_scope"], pv
        assert pv["server"].startswith("PostgreSQL") and pv["server_time"], pv
        tools = {t["tool"]: t["version"] for t in pv["tools"]}
        assert "pg_dump" in tools["pg_dump"], tools
        client.fail("test -e /target/pgd")
        client.fail("ls -d /dev/shm/dfcollect-db-*")
        code, stdout = client.execute(
            "dfcollect db postgres --host server --user examiner --password-file /root/pgpw --tls off"
            " --database nosuch -o /target/pgd -C CASE-DB -E db00 -e tester --dry-run --json"
        )
        assert code == 2 and json.loads(stdout)["missing"] == ["nosuch"], (code, stdout)

    with subtest("PostgreSQL: a custom-format dump per database, restorable"):
        code, stdout = client.execute(
            "dfcollect db postgres --host server --user examiner --password-file /root/pgpw --tls off"
            " -o /target/pg -C CASE-DB -E db01 -e tester --json"
        )
        assert code == 0, (code, stdout)
        items = {i["path"]: i for i in (json.loads(l) for l in client.succeed("cat /target/pg/items.jsonl").splitlines())}
        assert {"globals", "postgres", "shop"} <= set(items), items
        assert all(i["status"] == "acquired" for i in items.values()), items
        dump = member("/target/pg", "postgres/shop.dump")
        assert "TABLE DATA public items" in client.succeed(f"pg_restore -l {dump}")
        assert "alpha" in client.succeed(f"pg_restore -f - {dump}")
        manifest = json.loads(client.succeed("cat /target/pg/manifest.json"))
        ident = manifest["source"]["identity"]
        assert ident["version"].startswith("PostgreSQL") and ident["time_zone"], ident
        client.fail("grep -r pg-pass-123 /target/pg")
        client.fail("ls -d /dev/shm/dfcollect-db-*")
        client.succeed("dfcollect verify /target/pg")

    with subtest("PostgreSQL: --database narrows, the rest is counted out of scope"):
        code, stdout = client.execute(
            "dfcollect db postgres --host server --user examiner --password-file /root/pgpw --tls off"
            " --database shop -o /target/pg2 -C CASE-DB -E db02 -e tester --json"
        )
        assert code == 0, (code, stdout)
        manifest = json.loads(client.succeed("cat /target/pg2/manifest.json"))
        assert manifest["totals"]["unlisted_out_of_scope"] == {"database postgres not named with --database": 1}, manifest["totals"]
        client.fail("dfcollect db postgres --host server --user examiner --password-file /root/pgpw --tls off --database nosuch -o /target/pg3 -C C -E E -e t")

    with subtest("MariaDB: --tls prefer (the default) falls back on a server without TLS"):
        code, stdout = client.execute(
            "dfcollect db mariadb --host server --user examiner --password-file /root/mypw --database shop"
            " -o /target/my0 -C CASE-DB -E db04 -e tester --json"
        )
        assert code == 0, (code, stdout)

    with subtest("MariaDB: a dry run lists the databases with sizes"):
        code, stdout = client.execute(
            "dfcollect db mariadb --host server --user examiner --password-file /root/mypw --tls off"
            " -o /target/myd -C CASE-DB -E db05 -e tester --dry-run --json"
        )
        assert code == 0, (code, stdout)
        pv = json.loads(stdout)
        dbs = {d["name"]: d for d in pv["databases"]}
        assert "shop" in dbs and "information_schema" not in dbs, pv
        assert dbs["shop"]["bytes"] is not None, pv
        assert "MariaDB" in pv["server"], pv
        client.fail("test -e /target/myd")

    with subtest("MariaDB: a consistent SQL dump per database"):
        code, stdout = client.execute(
            "dfcollect db mariadb --host server --user examiner --password-file /root/mypw --tls off"
            " -o /target/my -C CASE-DB -E db03 -e tester --json"
        )
        assert code == 0, (code, stdout)
        items = {i["path"]: i for i in (json.loads(l) for l in client.succeed("cat /target/my/items.jsonl").splitlines())}
        assert "shop" in items and "mysql" in items and "information_schema" not in items, items
        dump = member("/target/my", "mariadb/shop.sql")
        text = client.succeed(f"cat {dump}")
        assert "INSERT INTO `items` VALUES" in text and "'alpha'" in text, text[:500]
        ident = json.loads(client.succeed("cat /target/my/manifest.json"))["source"]["identity"]
        assert "MariaDB" in ident["version"], ident
        client.fail("grep -r my-pass-123 /target/my")
        client.succeed("dfcollect verify /target/my")

    with subtest("TUI interactive run: password prompted once on preview, masked, and reused for run"):
        tui = TuiDriver(client)
        tui.start()
        tui.wait_for_text("dfcollect")
        tui.send_keys("d")
        tui.wait_for_text("Database dump")

        tui.fill_field("Case number", "CASE-DB")
        tui.fill_field("Evidence number", "tui-db01")
        tui.fill_field("Examiner", "tester")
        tui.fill_field("Host", "server")
        tui.fill_field("User", "examiner")
        tui.cycle_field("TLS mode", "off")
        tui.fill_field("Output dir", "/target/tui-pg")

        # Start preview
        tui.send_keys("F2")
        tui.wait_for_text("Credential Required")

        # Type password while modal is displayed
        tui.type_string("pg-pass-123")
        scr = tui.capture()
        assert "pg-pass-123" not in scr, "password leaked to screen"
        assert "•••••••••••" in scr, "password bullets missing"
        hist = tui.capture(full_history=True)
        assert "pg-pass-123" not in hist, "password leaked to tmux history"

        # Submit password
        tui.send_keys("Enter")
        tui.wait_for_text("Enter start", timeout=45)

        # Confirm start
        tui.send_keys("Enter")
        tui.wait_for_text("Confirm Acquisition Start")
        tui.send_keys("y")

        # Result: verify password prompt is NOT displayed again and run completes
        tui.wait_for_text("Acquisition Result", timeout=45)
        tui.wait_for_text("Status      : COMPLETE")
        tui.wait_for_text("q quit")
        assert "pg-pass-123" not in tui.capture(full_history=True), "password leaked during run"

        tui.send_keys("q")
        tui.wait_for_exit()

        manifest = json.loads(client.succeed("cat /target/tui-pg/manifest.json"))
        assert manifest["status"] == "complete", manifest
        client.succeed("dfcollect verify /target/tui-pg")
        client.fail("grep -r pg-pass-123 /target/tui-pg")
        items = {i["path"]: i for i in (json.loads(l) for l in client.succeed("cat /target/tui-pg/items.jsonl").splitlines())}
        assert {"globals", "postgres", "shop"} <= set(items), items
        dump = member("/target/tui-pg", "postgres/shop.dump")
        assert "alpha" in client.succeed(f"pg_restore -f - {dump}")
  '';
}
