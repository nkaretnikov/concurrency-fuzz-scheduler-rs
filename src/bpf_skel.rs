// Pulls in the libbpf-rs skeleton that BpfBuilder generated in build.rs from
// src/bpf/main.bpf.c.
include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
