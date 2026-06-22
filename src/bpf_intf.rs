// Pulls in the bindgen output for the structs shared with the BPF scheduler
// (fuzz_event, fuzz_config), generated into OUT_DIR by BpfBuilder from
// src/bpf/intf.h.
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
