{
  description = "Logical forensic acquisition with scope, per-item hashes, manifest and audit records";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Shared safety core, a sibling Cargo path dependency
    dfcore = {
      url = "github:tylerstyle/dfcore";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, dfcore }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        dfcollect = pkgs.callPackage ./package.nix { dfcoreSrc = dfcore; };
      in
      {
        packages = {
          default = dfcollect;
          dfcollect = dfcollect;
        };

        apps = {
          default = flake-utils.lib.mkApp { drv = dfcollect; };
          dfcollect = flake-utils.lib.mkApp { drv = dfcollect; };
        };

        # VM test against read-only local, SMB and NFS mounts
        checks = pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          vm = import ./tests/vm.nix { inherit pkgs dfcollect; };
          imap = import ./tests/imap.nix { inherit pkgs dfcollect; };
          graph = import ./tests/graph.nix { inherit pkgs dfcollect; };
          cloud = import ./tests/cloud.nix { inherit pkgs dfcollect; };
          db = import ./tests/db.nix { inherit pkgs dfcollect; };
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ dfcollect ];
          buildInputs = with pkgs; [ rustc cargo rustfmt clippy ];
        };
      }
    );
}
