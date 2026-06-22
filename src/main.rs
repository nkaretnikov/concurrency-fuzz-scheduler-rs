// Rust port of https://github.com/parttimenerd/concurrency-fuzz-scheduler.
//
// Like the original (Java + hello-ebpf), the random run/sleep policy executes
// inside a sched_ext BPF program in the kernel (see src/bpf/main.bpf.c); this
// keeps the scheduling decision out of user space, so that under a
// deterministic hypervisor (Bedrock) a run is reproducible from a seed. The
// Rust here is only the loader and campaign supervisor.
//
// main() wires two threads together: the loader (which attaches the scheduler
// and drains its event log) on the main thread, and the campaign supervisor
// (which launches and watches the target) on a second thread. They share only
// a handful of atomics.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

mod diagram;
mod duration;
mod fuzz;
mod supervisor;

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;

use duration::{nanoseconds_to_string, DurationRange};
use fuzz::FuzzScheduler;

#[derive(Parser)]
#[command(
    name = "scheduler.sh",
    version,
    about = "Linux scheduler that produces random scheduling edge cases to fuzz concurrent applications, runs till error"
)]
struct Cli {
    /// Script or command to execute.
    script: String,

    /// Range of sleep lengths.
    #[arg(short = 's', long = "sleep", default_value = "10ms,2000ms", value_parser = parse_duration_range)]
    sleep_range: DurationRange,

    /// Range of running time lengths.
    #[arg(short = 'r', long = "run", default_value = "1ms,100ms", value_parser = parse_duration_range)]
    run_range: DurationRange,

    /// Time slice duration for all non-script tasks.
    #[arg(long = "system-slice", default_value = "5ms", value_parser = parse_duration_ns)]
    system_slice_ns: u64,

    /// Time slice duration for the script.
    #[arg(long = "slice", default_value = "5ms", value_parser = parse_duration_ns)]
    slice_ns: u64,

    /// Command to execute on error, default checks for error code != 0.
    #[arg(short = 'e', long = "error-command", default_value = "")]
    error_command: String,

    /// Time to run the script for at a time, restart the whole process
    /// afterwards, ignored with timeout != -1.
    #[arg(short = 'i', long = "iteration-time", default_value = "100s", value_parser = parse_duration_ns)]
    iteration_time_ns: u64,

    /// Don't scale the slice time with the number of waiting tasks.
    #[arg(short = 'd', long = "dont-scale-slice", default_value_t = false)]
    dont_scale_slice: bool,

    /// Maximum number of iterations.
    #[arg(short = 'm', long = "max-iterations", default_value_t = -1)]
    max_iterations: i32,

    /// Time between two checks via the error script.
    #[arg(long = "error-check-interval", default_value = "10s", value_parser = parse_duration_ns)]
    error_check_interval_ns: u64,

    /// Log the state changes.
    #[arg(long = "log", default_value_t = false)]
    log: bool,

    /// Seed for the in-kernel PRNG. The same seed reproduces the same schedule
    /// (under a deterministic guest such as Bedrock with a single vCPU).
    /// Accepts decimal or 0x-prefixed hex.
    #[arg(long = "seed", default_value_t = 0x9e37_79b9_7f4a_7c15, value_parser = parse_seed)]
    seed: u64,

    /// Maximum time in seconds for a single iteration before treating it as an
    /// error/timeout (default: -1, disabled).
    #[arg(short = 't', long = "timeout", default_value_t = -1)]
    timeout_seconds: i64,
}

fn parse_duration_ns(s: &str) -> Result<u64, String> {
    duration::parse_to_nanoseconds(s).map_err(|e| e.to_string())
}

fn parse_duration_range(s: &str) -> Result<DurationRange, String> {
    DurationRange::parse(s).map_err(|e| e.to_string())
}

// Accept a seed as decimal or 0x-prefixed hex.
fn parse_seed(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let result = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => s.parse::<u64>(),
    };
    result.map_err(|_| format!("invalid seed: {s}"))
}

/// Read only configuration shared with both threads.
#[derive(Clone)]
pub struct Config {
    pub script: String,
    pub sleep_range: DurationRange,
    pub run_range: DurationRange,
    pub system_slice_ns: u64,
    pub slice_ns: u64,
    pub error_command: String,
    pub iteration_time_ns: u64,
    pub scale_slice: bool,
    pub max_iterations: i32,
    pub error_check_interval_ns: u64,
    pub log: bool,
    pub timeout_seconds: i64,
    pub seed: u64,
}

impl Config {
    pub fn in_timeout_mode(&self) -> bool {
        self.timeout_seconds != -1
    }

    pub fn error_check_interval(&self) -> Duration {
        Duration::from_nanos(self.error_check_interval_ns)
    }

    pub fn iteration_time(&self) -> Duration {
        Duration::from_nanos(self.iteration_time_ns)
    }
}

/// Mutable state shared between the scheduler thread and the supervisor thread.
pub struct Shared {
    /// Pid of the target process to fuzz, 0 means none.
    pub script_pid: AtomicI32,
    /// Bumped on each new iteration so the scheduler drops stale per task state.
    pub generation: AtomicU64,
    /// Set once the scheduler is attached and ready.
    pub attached: AtomicBool,
    /// Set to ask both threads to stop.
    pub done: AtomicBool,
}

impl Shared {
    fn new() -> Self {
        Self {
            script_pid: AtomicI32::new(0),
            generation: AtomicU64::new(0),
            attached: AtomicBool::new(false),
            done: AtomicBool::new(false),
        }
    }
}

fn print_warning() {
    // While attached, this sched_ext scheduler schedules every task on the
    // system, not just the target, and deliberately stalls threads at random.
    eprintln!(
        "WARNING: this is an experimental sched_ext scheduler proof of concept. \
         It schedules the whole system while attached; do not run it on a machine \
         you care about."
    );
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config {
        script: cli.script,
        sleep_range: cli.sleep_range,
        run_range: cli.run_range,
        system_slice_ns: cli.system_slice_ns,
        slice_ns: cli.slice_ns,
        error_command: cli.error_command,
        iteration_time_ns: cli.iteration_time_ns,
        scale_slice: !cli.dont_scale_slice,
        max_iterations: cli.max_iterations,
        error_check_interval_ns: cli.error_check_interval_ns,
        log: cli.log,
        timeout_seconds: cli.timeout_seconds,
        seed: cli.seed,
    };

    print_warning();
    if cfg.log {
        println!(
            "sleep range: {}, run range: {}, system slice: {}, slice: {}, seed: {:#x}",
            cfg.sleep_range,
            cfg.run_range,
            nanoseconds_to_string(cfg.system_slice_ns, 3),
            nanoseconds_to_string(cfg.slice_ns, 3),
            cfg.seed,
        );
    }

    let shared = Arc::new(Shared::new());

    // Launch the supervisor first; it waits for the scheduler to attach before
    // it starts the target.
    let supervisor = {
        let cfg = cfg.clone();
        let shared = shared.clone();
        thread::spawn(move || supervisor::run(cfg, shared))
    };

    // Load and attach the scheduler on the main thread. The BPF skeleton holds
    // a raw object pointer and is not Send, so it has to stay here.
    let mut open_object = MaybeUninit::uninit();
    let result = match FuzzScheduler::init(&mut open_object, cfg, shared.clone()) {
        Ok(mut scheduler) => scheduler.run().map(|_| ()),
        Err(e) => Err(e),
    };

    // Whatever happened, make sure the supervisor stops too.
    shared.done.store(true, Ordering::SeqCst);
    let _ = supervisor.join();

    result
}
