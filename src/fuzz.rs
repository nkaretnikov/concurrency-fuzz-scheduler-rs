// Loader and supervisor-facing side of the in-kernel fuzzing scheduler.
//
// Unlike the user-space port (which ran the run/sleep policy here in Rust on
// top of scx_rustland_core), all scheduling decisions now live in the BPF
// program in src/bpf/main.bpf.c. This file only:
//   - opens the skeleton, pushes the read-only config (ranges, slices, seed)
//     into rodata, loads it, and attaches the sched_ext struct_ops;
//   - while attached, writes the current target pid and generation into the
//     config map so the kernel knows which process to fuzz;
//   - drains the ring buffer of run/sleep events and prints them / feeds the
//     diagram, exactly as the old policy logged directly.
//
// NOTE: not compiled in this environment. The libbpf-rs skeleton accessors
// (rodata_data, maps, the scx macros) are version sensitive; spots most likely
// to need a tweak against your libbpf-rs / scx_utils are marked "REVIEW:".

use std::cell::RefCell;
use std::mem::MaybeUninit;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapFlags, OpenObject, RingBufferBuilder};
use scx_utils::{scx_ops_attach, scx_ops_load, scx_ops_open, uei_exited, uei_report, UserExitInfo};

use crate::bpf_intf::*;
use crate::bpf_skel::*;
use crate::diagram::{DiagramHelper, EventType};
use crate::{Config, Shared};

// The shared structs are plain old data, so they can be read from / written to
// raw map bytes.
unsafe impl plain::Plain for fuzz_event {}
unsafe impl plain::Plain for fuzz_config {}

// event_type values, kept as literals to avoid depending on the exact bindgen
// constant names for the C enum.
const EVENT_RUNNING: u32 = 0;

const POLL_TIMEOUT: Duration = Duration::from_millis(100);

// Timing references for the log output, shared between the ring buffer callback
// and the main loop (single threaded, so Rc<RefCell<..>> is enough).
struct LogState {
    diagram: DiagramHelper,
    global_start: Instant,
    gen_start: Instant,
}

pub struct FuzzScheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    shared: Arc<Shared>,
    log_state: Rc<RefCell<LogState>>,
    generation: u64,
}

impl<'a> FuzzScheduler<'a> {
    pub fn init(
        open_object: &'a mut MaybeUninit<OpenObject>,
        cfg: Config,
        shared: Arc<Shared>,
    ) -> Result<Self> {
        let skel_builder = BpfSkelBuilder::default();
        // The 4th arg is Option<bpf_object_open_opts>; None uses the default
        // open path. Typed so the macro's Some(..) arm can be type-checked.
        let mut open_skel = scx_ops_open!(
            skel_builder,
            open_object,
            fifo_fuzz_ops,
            None::<libbpf_rs::libbpf_sys::bpf_object_open_opts>
        )?;

        // Read-only configuration must be set before the program is loaded.
        // REVIEW: rodata_data access form is libbpf-rs version sensitive.
        let rodata = open_skel
            .maps
            .rodata_data
            .as_mut()
            .context("BPF rodata not available")?;
        rodata.run_min_ns = cfg.run_range.min_ns;
        rodata.run_max_ns = cfg.run_range.max_ns;
        rodata.sleep_min_ns = cfg.sleep_range.min_ns;
        rodata.sleep_max_ns = cfg.sleep_range.max_ns;
        rodata.slice_ns = cfg.slice_ns;
        rodata.system_slice_ns = cfg.system_slice_ns;
        rodata.scale_slice = cfg.scale_slice;
        rodata.logging = cfg.log;
        rodata.seed = cfg.seed;

        let mut skel = scx_ops_load!(open_skel, fifo_fuzz_ops, uei)?;
        let struct_ops = scx_ops_attach!(skel, fifo_fuzz_ops)?;

        // Start with no target, then let the supervisor begin launching it.
        write_config(&skel, 0, 0)?;
        shared.attached.store(true, Ordering::SeqCst);

        let now = Instant::now();
        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            shared,
            log_state: Rc::new(RefCell::new(LogState {
                diagram: DiagramHelper::new(),
                global_start: now,
                gen_start: now,
            })),
            generation: 0,
        })
    }

    pub fn run(&mut self) -> Result<UserExitInfo> {
        // Drain run/sleep events from the kernel.
        let log_state = self.log_state.clone();
        let mut rbb = RingBufferBuilder::new();
        rbb.add(&self.skel.maps.events, move |data: &[u8]| -> i32 {
            match plain::from_bytes::<fuzz_event>(data) {
                Ok(event) => handle_event(&log_state, event),
                Err(_) => {}
            }
            0
        })?;
        let ring = rbb.build()?;

        while !uei_exited!(&self.skel, uei) && !self.shared.done.load(Ordering::SeqCst) {
            // A new iteration resets the per-task log timer.
            let generation = self.shared.generation.load(Ordering::SeqCst);
            if generation != self.generation {
                self.generation = generation;
                self.log_state.borrow_mut().gen_start = Instant::now();
            }

            // Tell the kernel which process to fuzz and which generation we are
            // in. The kernel drops stale per-task state when the generation
            // changes, mirroring sync_generation() in the old policy.
            let pid = self.shared.script_pid.load(Ordering::SeqCst) as u32;
            write_config(&self.skel, pid, generation as u32)?;

            let _ = ring.poll(POLL_TIMEOUT);
        }

        // Detach by dropping the struct_ops link.
        self.struct_ops = None;
        Ok(uei_report!(&self.skel, uei)?)
    }
}

// Write the runtime config (target pid and generation) into the single-entry
// config map. Uses a shared (&) borrow so it coexists with the ring buffer's
// borrow of the events map.
fn write_config(skel: &BpfSkel, target_tgid: u32, generation: u32) -> Result<()> {
    let cfg = fuzz_config {
        target_tgid,
        generation,
    };
    let key: u32 = 0;
    skel.maps
        .config_map
        .update(
            &key.to_ne_bytes(),
            unsafe { plain::as_bytes(&cfg) },
            MapFlags::ANY,
        )
        .context("failed to update config map")?;
    Ok(())
}

fn handle_event(log_state: &Rc<RefCell<LogState>>, event: &fuzz_event) {
    let mut state = log_state.borrow_mut();
    let overall = state.global_start.elapsed().as_secs_f64();
    let iteration = state.gen_start.elapsed().as_secs_f64();
    let comm = comm_to_string(&event.comm);
    let millis = event.duration_ns / 1_000_000;
    let (verb, event_type) = if event.event_type == EVENT_RUNNING {
        ("running", EventType::Running)
    } else {
        ("sleeping", EventType::Sleeping)
    };
    state
        .diagram
        .record_event(overall, &comm, event_type, event.duration_ns as f64 / 1_000_000_000.0);
    println!("[{overall:6.3}|{iteration:6.3}] {comm} is {verb} for {millis}ms");
}

// The comm field is a NUL terminated char array; render it as a String. Read it
// as raw bytes so it works whether bindgen typed the C `char` as i8 or u8.
fn comm_to_string(comm: &[std::os::raw::c_char]) -> String {
    let bytes = unsafe { std::slice::from_raw_parts(comm.as_ptr() as *const u8, comm.len()) };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
