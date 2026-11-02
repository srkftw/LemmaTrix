# Public, architecture-neutral source pin; no developer-specific store paths.
# Evaluates on x86_64-linux and aarch64-linux. Setup selects the native system.
{ system ? builtins.currentSystem }:
let
  source = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/f20cd90e28fe0403873f473b29e42662cd86e8c4.tar.gz";
    sha256 = "sha256-MTJCMrhDFb+GRbLxBPTp8kB4dDlO+egmQ5qsJgYuaWw=";
  };
  pkgs = import source { inherit system; };
  llvm = pkgs.llvmPackages_20;
  tools = {
    lean = "${pkgs.lean4}/bin/lean";
    clang = "${llvm.clang-unwrapped}/bin/clang";
    "ld.lld" = "${llvm.lld}/bin/ld.lld";
    "llvm-objcopy" = "${llvm.llvm}/bin/llvm-objcopy";
    "llvm-nm" = "${llvm.llvm}/bin/llvm-nm";
    "llvm-readelf" = "${llvm.llvm}/bin/llvm-readelf";
    python = "${pkgs.python3}/bin/python3";
  };
in assert builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
  pkgs.writeText "lemmatrix-native-toolchain.json" (builtins.toJSON {
    schema = 1;
    inherit system tools;
    source = "nixpkgs:f20cd90e28fe0403873f473b29e42662cd86e8c4";
    isolation = "linux-user-mount-net-pid-namespaces";
  })
