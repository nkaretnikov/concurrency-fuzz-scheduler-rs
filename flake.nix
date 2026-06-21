{
  description = "Dev shell for the concurrency fuzz scheduler (Rust port)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      # sched_ext is Linux only, so only Linux systems are offered.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          name = "concurrency-fuzz-scheduler-rs";

          # Tools that run on the build host. clang and llvm are needed to
          # compile the bundled BPF backend; bpftool generates vmlinux.h and the
          # skeleton; the rust tools build the user-space scheduler; gcc and
          # make build the C sample.
          nativeBuildInputs = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
            clang
            llvm
            bpftools
            pkg-config
            gnumake
            gcc
          ];

          # Libraries linked by libbpf-rs / libbpf-sys and the scx crates.
          buildInputs = with pkgs; [
            libbpf
            elfutils
            zlib
            zstd
            libseccomp
          ];

          # The BPF target rejects this hardening flag that the Nix cc-wrapper
          # would otherwise inject into the clang invocation.
          hardeningDisable = [ "zerocallusedregs" ];

          # bindgen (used by libbpf-cargo and scx_utils) needs to find libclang.
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          shellHook = ''
            echo "concurrency-fuzz-scheduler-rs dev shell"
            echo "  $(cargo --version)"
            echo "  $(clang --version | head -1)"
            echo "  bpftool: $(command -v bpftool)"
            echo
            echo "Build:  cargo build --release"
            echo "Note:   needs a kernel with"
            echo "        CONFIG_SCHED_CLASS_EXT=y and CONFIG_DEBUG_INFO_BTF=y"
            echo "        (check: ls /sys/kernel/sched_ext and /sys/kernel/btf/vmlinux)."
          '';
        };
      });
    };
}
