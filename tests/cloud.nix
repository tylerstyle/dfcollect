# dfcollect cloud against an S3 server (rclone serve s3) through rclone: files with
# known modification times in two folders; the scope takes a time window and
# excludes a folder. The stored files must be the uploaded bytes, MD5 must
# match the provider's hash, the secret must not reach the record, and a file
# uploaded during a (throttled) acquisition must show up as a remote change.
#
#   nix-build tests/cloud.nix          (dfcore from ../dfcore)
{ pkgs ? import <nixpkgs> { }
, dfcollect ? pkgs.callPackage ../package.nix { }
}:

pkgs.testers.runNixOSTest {
  name = "dfcollect-cloud";

  nodes.server = {
    networking.firewall.allowedTCPPorts = [ 9000 ];
    # An S3 server over a directory; ETags are the objects' MD5
    systemd.services.s3 = {
      wantedBy = [ "multi-user.target" ];
      preStart = "mkdir -p /srv/s3";
      serviceConfig.ExecStart = "${pkgs.rclone}/bin/rclone serve s3 /srv/s3 --addr :9000 --auth-key examiner,minio-secret-key-123";
    };
  };

  nodes.client = {
    environment.systemPackages = [ dfcollect pkgs.rclone pkgs.python3 ];
    environment.etc."rclone.conf".text = ''
      [evidence]
      type = s3
      provider = Rclone
      env_auth = false
      access_key_id = examiner
      secret_access_key = minio-secret-key-123
      endpoint = http://server:9000
    '';
  };

  testScript = ''
    import json

    rc = "rclone --config /etc/rclone.conf"
    start_all()
    server.wait_for_unit("s3.service")
    server.wait_for_open_port(9000)
    client.wait_for_unit("multi-user.target")
    client.succeed(
        "mkdir -p /root/src/docs /root/src/private /target"
        " && printf 'alpha\\n' > /root/src/docs/a.txt && touch -d '2026-03-01 10:00:00Z' /root/src/docs/a.txt"
        " && head -c 3145728 /dev/urandom > /root/src/docs/b.bin && touch -d '2026-04-01 10:00:00Z' /root/src/docs/b.bin"
        " && printf 'old\\n' > /root/src/docs/old.txt && touch -d '2025-06-01 10:00:00Z' /root/src/docs/old.txt"
        " && printf 'private\\n' > /root/src/private/c.txt && touch -d '2026-03-15 10:00:00Z' /root/src/private/c.txt"
    )
    client.wait_until_succeeds(f"{rc} mkdir evidence:case", timeout=60)
    client.succeed(f"{rc} copy /root/src evidence:case")

    def run(out, *extra):
        return client.execute(
            f"dfcollect cloud evidence:case --rclone-config /etc/rclone.conf -o {out}"
            " -C CASE-CLOUD -E cloud01 -e tester --exclude 'private/**'"
            " --not-before 2026-01-01T00:00:00Z --not-after 2026-07-01T00:00:00Z --json " + " ".join(extra)
        )

    with subtest("in-scope files arrive byte for byte and match the provider's MD5"):
        code, stdout = run("/target/c1")
        assert code == 0, (code, stdout)
        summary = json.loads(stdout)
        assert summary["files"] == 2, summary
        items = {i["path"]: i for i in (json.loads(l) for l in client.succeed("cat /target/c1/items.jsonl").splitlines())}
        for path in ["docs/a.txt", "docs/b.bin"]:
            item = items[path]
            assert item["status"] == "acquired", item
            assert item["metadata"]["provider_hash_checks"] == {"md5": "match"}, item
            want = client.succeed(f"sha256sum /root/src/{path}").split()[0]
            assert item["hashes"]["sha256"] == want, item
        assert items["docs/a.txt"]["times"]["modified"].startswith("2026-03-01T10:00:00"), items["docs/a.txt"]
        assert items["rclone/listing-before.json"]["kind"] == "listing", items
        assert "rclone/listing-after.json" in items, items
        manifest = json.loads(client.succeed("cat /target/c1/manifest.json"))
        assert sum(manifest["totals"]["unlisted_out_of_scope"].values()) == 2, manifest["totals"]
        config = manifest["source"]["identity"]["config"]
        assert "secret_access_key = <removed>" in config and "minio-secret-key" not in config, config
        assert "minio-secret-key" not in client.succeed("cat /target/c1/*.jsonl /target/c1/manifest.json")
        assert summary["remote_changes"]["added"] == [], summary
        client.succeed("dfcollect verify /target/c1")

    with subtest("a file uploaded during the acquisition shows as a remote change"):
        client.succeed("printf 'late\\n' > /root/late.txt && touch -d '2026-05-01 10:00:00Z' /root/late.txt")
        client.succeed(
            "systemd-run --unit c2 dfcollect cloud evidence:case --rclone-config /etc/rclone.conf"
            " --rclone-arg=--bwlimit=500k -o /target/c2 -C CASE-CLOUD -E cloud02 -e tester"
        )
        client.wait_until_succeeds("test -s /target/c2/footprint.jsonl")
        client.succeed("sleep 2")
        client.succeed(f"{rc} copyto /root/late.txt evidence:case/docs/late.txt")
        client.wait_until_fails("systemctl is-active c2", timeout=120)
        manifest = json.loads(client.succeed("cat /target/c2/manifest.json"))
        assert manifest["status"] == "complete_with_errors", manifest
        assert any("remote changed" in e for e in manifest["errors"]), manifest["errors"]
        footprint = [json.loads(l) for l in client.succeed("cat /target/c2/footprint.jsonl").splitlines()]
        changes = [f["detail"]["during_acquisition"] for f in footprint if f["kind"] == "remote_changes"][0]
        assert [c["Path"] for c in changes["added"]] == ["docs/late.txt"], changes
  '';
}
