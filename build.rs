// Compile the in-kernel BPF scheduler (src/bpf/main.bpf.c) and generate the
// libbpf-rs skeleton plus the bindgen bindings for the structs shared in
// src/bpf/intf.h. BpfBuilder (from scx_cargo) bundles vmlinux.h and the scx
// BPF headers, runs clang and bpftool, and writes bpf_skel.rs and bpf_intf.rs
// into OUT_DIR, where src/bpf_skel.rs and src/bpf_intf.rs include them.
//
// Unlike the user-space variant on scx_rustland_core, the scheduling policy is
// the C we maintain in src/bpf; scx_utils here is only build/loader plumbing,
// not part of the scheduling decision path.
fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .build()
        .unwrap();
}
