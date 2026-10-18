# dfcollect against real read-only mounts: a local ext4 disk, an SMB share
# and an NFS export of a second machine. Every source must be unchanged
# afterwards (content, times), every acquired hash must match the server's,
# and a read-write mount is refused.
#
#   nix-build tests/vm.nix            (dfcore from ../dfcore)
#   nix build .#checks.x86_64-linux.vm
{ pkgs ? import <nixpkgs> { }
, dfcollect ? pkgs.callPackage ../package.nix { }
}:

pkgs.testers.runNixOSTest {
  name = "dfcollect-mounts";

  nodes.server = {
    networking.firewall.enable = false;
    services.samba = {
      enable = true;
      settings = {
        global."map to guest" = "Bad User";
        evidence = {
          path = "/srv/evidence";
          "read only" = "yes";
          "guest ok" = "yes";
        };
      };
    };
    services.nfs.server = {
      enable = true;
      exports = "/srv/evidence *(ro,no_subtree_check,insecure,all_squash)";
    };
  };

  nodes.client = {
    networking.firewall.enable = false;
    virtualisation.emptyDiskImages = [ 64 256 ];
    boot.supportedFilesystems = [ "cifs" "nfs" ];
    environment.systemPackages = [ dfcollect pkgs.cifs-utils pkgs.nfs-utils pkgs.e2fsprogs pkgs.python3 pkgs.tmux ];
  };

  testScript = ''
    ${builtins.readFile ./tui.py}
    import json

    def tree(machine, root):
        """path -> (sha256, mtime_ns) of every regular file below root"""
        out = machine.succeed(
            f"cd {root} && find . -type f -printf '%P\\t%T@\\n' | sort"
        )
        hashes = machine.succeed(f"cd {root} && find . -type f -print0 | sort -z | xargs -0 sha256sum")
        h = {line.split("  ", 1)[1].removeprefix("./"): line.split("  ")[0] for line in hashes.splitlines()}
        return {p: (h[p], t) for p, t in (l.split("\t") for l in out.splitlines())}

    def fill(machine, root):
        machine.succeed(
            f"mkdir -p {root}/docs/private {root}/other"
            f" && printf 'report' > {root}/docs/report.txt"
            f" && printf 'diary' > {root}/docs/private/diary.txt"
            f" && printf 'notes' > {root}/other/notes.txt"
            f" && head -c 3000000 /dev/urandom > {root}/docs/big.bin"
            f" && touch -d '2026-03-01 12:00:00 UTC' {root}/docs/report.txt"
            f" && touch -d '2025-01-01 12:00:00 UTC' {root}/docs/big.bin"
        )

    def collect(source, out, *extra):
        cmd = (
            f"dfcollect files {source} -o {out} -C CASE-VM -E {out.split('/')[-1]} -e tester"
            " --include 'docs/**' --exclude 'docs/private/**' --json " + " ".join(extra)
        )
        return client.execute(cmd)

    def items(out):
        return [json.loads(l) for l in client.succeed(f"cat {out}/items.jsonl").splitlines()]

    start_all()
    server.wait_for_unit("samba-smbd.service")
    server.wait_for_unit("nfs-server.service")
    fill(server, "/srv/evidence")
    server.succeed("sync")
    server_before = tree(server, "/srv/evidence")

    client.wait_for_unit("multi-user.target")
    # vdb: evidence disk, vdc: target disk
    client.succeed("mkfs.ext4 -q /dev/vdb && mkdir -p /mnt/ev && mount /dev/vdb /mnt/ev")
    fill(client, "/mnt/ev")
    client.succeed("mkdir -p /mnt/ev/delivery && printf 'payload\n' > /mnt/ev/delivery/data.txt")
    client.succeed("umount /mnt/ev && mount -o ro,noload /dev/vdb /mnt/ev")
    local_before = tree(client, "/mnt/ev")
    client.succeed("mkfs.ext4 -q /dev/vdc && mkdir -p /target && mount /dev/vdc /target")
    client.succeed("mkdir -p /mnt/smb /mnt/nfs")
    client.succeed("mount -t cifs -o ro,guest,vers=3.1.1 //server/evidence /mnt/smb")
    client.succeed("mount -t nfs -o ro,vers=4.2 server:/srv/evidence /mnt/nfs")

    with subtest("each read-only source is acquired within the scope and verifies"):
        for name, source in [("local", "/mnt/ev"), ("smb", "/mnt/smb"), ("nfs", "/mnt/nfs")]:
            out = f"/target/{name}"
            code, stdout = collect(source, out)
            assert code == 0, (name, code, stdout)
            summary = json.loads(stdout)
            # report.txt and big.bin; "docs" itself does not match docs/**
            assert summary["acquired"] == 2, (name, summary)
            print(name, "footprint:", client.succeed(f"cat {out}/footprint.jsonl"))
            got = {i["path"]: i for i in items(out)}
            want = local_before if name == "local" else server_before
            for path in ["docs/report.txt", "docs/big.bin"]:
                assert got[path]["hashes"]["sha256"] == want[path][0], (name, path)
            assert got["docs/report.txt"]["times"]["modified"].startswith("2026-03-01T12:00:00"), got
            text = client.succeed(f"cat {out}/items.jsonl {out}/manifest.json")
            assert "diary" not in text and "notes" not in text, (name, "out-of-scope name recorded")
            client.succeed(f"dfcollect verify {out}")

    with subtest("TUI interactive run: ingest package acquisition from read-only mount"):
        tui = TuiDriver(client)
        tui.start()
        tui.wait_for_text("dfcollect")
        tui.send_keys("i")
        tui.wait_for_text("Provider delivery package")

        tui.fill_field("Case number", "CASE-VM")
        tui.fill_field("Evidence number", "tui-ingest01")
        tui.fill_field("Examiner", "tester")
        tui.fill_field("Package path", "/mnt/ev/delivery")
        tui.fill_field("Provider", "Example Mail GmbH")
        tui.fill_field("Received at", "2026-03-01T12:00:00Z")
        tui.fill_field("Channel", "SFTP")
        tui.fill_field("Output dir", "/target/tui-ingest")

        # Start preview
        tui.send_keys("F2")
        tui.wait_for_text("Enter start", timeout=45)

        # Confirm start
        tui.send_keys("Enter")
        tui.wait_for_text("Confirm Acquisition Start")
        tui.send_keys("y")

        # Result
        tui.wait_for_text("Acquisition Result", timeout=45)
        tui.wait_for_text("Status      : COMPLETE")
        tui.wait_for_text("q quit")
        tui.send_keys("q")
        tui.wait_for_exit()

        manifest = json.loads(client.succeed("cat /target/tui-ingest/manifest.json"))
        assert manifest["status"] == "complete", manifest
        client.succeed("dfcollect verify /target/tui-ingest")
        items_list = [json.loads(l) for l in client.succeed("cat /target/tui-ingest/items.jsonl").splitlines()]
        assert any(i["path"] == "data.txt" and i["status"] == "acquired" for i in items_list), items_list
        assert manifest["source"]["kind"] == "provider-delivery", manifest["source"]

    with subtest("the sources are unchanged"):
        client.succeed("umount /mnt/smb /mnt/nfs")
        assert tree(server, "/srv/evidence") == server_before
        assert tree(client, "/mnt/ev") == local_before

    with subtest("a read-write mount and a destination on the source are refused"):
        client.succeed("umount /mnt/ev && mount /dev/vdb /mnt/ev")
        code, _ = collect("/mnt/ev", "/target/rw")
        assert code == 3, code
        client.succeed("umount /mnt/ev && mount -o ro,noload /dev/vdb /mnt/ev")
        code, _ = collect("/mnt/ev/docs", "/mnt/ev/out")
        assert code == 3, code
  '';
}
