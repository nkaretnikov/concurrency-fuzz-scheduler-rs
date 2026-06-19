// Pulls in the bindgen output for the scx_rustland_core backend's shared
// structs (queued_task_ctx, dispatched_task_ctx and friends), generated into
// OUT_DIR by RustLandBuilder.
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
