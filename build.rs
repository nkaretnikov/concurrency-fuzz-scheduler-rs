// The scheduling policy in this project lives entirely in Rust user space. The
// only BPF involved is the generic sched_ext backend that ships inside the
// scx_rustland_core crate, which forwards runnable tasks up to us and dispatches
// the tasks we hand back. RustLandBuilder unpacks that backend, compiles it,
// and generates the libbpf-rs skeleton plus the shared-struct bindings into
// OUT_DIR. We never write or maintain any C ourselves.
fn main() {
    scx_rustland_core::RustLandBuilder::new()
        .unwrap()
        .build()
        .unwrap();
}
