// Pulls in the libbpf-rs skeleton that the RustLandBuilder generated in
// build.rs from the scx_rustland_core backend.
include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
