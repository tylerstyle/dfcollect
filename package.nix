{ lib
, rustPlatform
, runCommand
  # dfcore is a sibling path dependency (../dfcore); flakes pass their input
, dfcoreSrc ? ../dfcore
}:

let
  clean = src: lib.cleanSourceWith {
    filter = path: type: baseNameOf path != "target";
    src = lib.cleanSource src;
  };
  # Lay out the sources as in ~/git so `path = "../dfcore"` resolves
  src = runCommand "dfcollect-src" { } ''
    mkdir -p $out
    cp -r ${clean ./.} $out/dfcollect
    cp -r ${clean dfcoreSrc} $out/dfcore
    chmod -R u+w $out
  '';
in
rustPlatform.buildRustPackage {
  pname = "dfcollect";
  version = "0.1.0";

  inherit src;
  sourceRoot = "dfcollect-src/dfcollect";

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  # The CLI tests run in /dev/shm, which the Nix sandbox provides
  meta = with lib; {
    description = "Logical forensic acquisition with scope, per-item hashes, manifest and audit records";
    homepage = "https://github.com/tylerstyle/dfcollect";
    license = with licenses; [ mit asl20 ];
    mainProgram = "dfcollect";
    platforms = platforms.linux;
  };
}
