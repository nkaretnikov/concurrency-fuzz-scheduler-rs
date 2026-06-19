// Drives the fuzzing campaign: it launches the target program, tells the
// scheduler which pid to fuzz, and supervises the run until the program
// crashes, an error command fires, the iteration time elapses, or a timeout
// hits. This is the port of the iteration and run logic from Main.java.
//
// It runs on its own thread because the scheduler policy keeps the main thread
// busy dispatching tasks. The two communicate only through the shared atomics.

use std::process::{Child, Command};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::{Config, Shared};

const POLL_INTERVAL: Duration = Duration::from_millis(100);

struct IterationResult {
    duration_seconds: f64,
    did_fail: bool,
}

pub fn run(cfg: Config, shared: Arc<Shared>) {
    // Wait until the scheduler is attached before launching anything, so the
    // target runs under our policy from the start.
    while !shared.attached.load(Ordering::SeqCst) && !shared.done.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(10));
    }
    if shared.done.load(Ordering::SeqCst) {
        return;
    }

    let start_of_fuzzing = Instant::now();
    let mut iteration_durations: Vec<f64> = Vec::new();

    let mut i = 0;
    while (cfg.max_iterations < 0 || i < cfg.max_iterations) && !shared.done.load(Ordering::SeqCst) {
        let result = match iteration(&cfg, &shared) {
            Ok(result) => result,
            Err(e) => {
                eprintln!("{e:?}");
                break;
            }
        };
        iteration_durations.push(result.duration_seconds);

        if cfg.log {
            print_iteration_stats(&iteration_durations);
            println!();
        }

        if result.did_fail {
            println!(
                "Program failed after {:.3}",
                start_of_fuzzing.elapsed().as_secs_f64()
            );
            break;
        }

        i += 1;
    }

    if !iteration_durations.is_empty() && !cfg.log {
        print_iteration_stats(&iteration_durations);
    }

    // Tell the scheduler thread to wind down.
    shared.done.store(true, Ordering::SeqCst);
}

fn iteration(cfg: &Config, shared: &Arc<Shared>) -> Result<IterationResult> {
    println!("Iteration");
    let iteration_start = Instant::now();
    let mut did_fail = false;

    // Stop fuzzing the previous pid and bump the generation so the scheduler
    // drops its stale per task state before the new target appears.
    shared.script_pid.store(0, Ordering::SeqCst);
    shared.generation.fetch_add(1, Ordering::SeqCst);

    let mut child: Child = Command::new(&cfg.script)
        .spawn()
        .with_context(|| format!("failed to start target: {}", cfg.script))?;

    shared
        .script_pid
        .store(child.id() as i32, Ordering::SeqCst);

    let start = Instant::now();
    let mut last_error_check = Instant::now();

    loop {
        if shared.done.load(Ordering::SeqCst) {
            break;
        }
        thread::sleep(POLL_INTERVAL);

        if let Some(status) = child.try_wait().context("failed to poll target")? {
            if !status.success() {
                did_fail = true;
            }
            break;
        }

        if last_error_check.elapsed() >= cfg.error_check_interval() {
            if does_error_script_succeed(cfg) {
                did_fail = true;
                break;
            }
            last_error_check = Instant::now();
        }

        if !cfg.in_timeout_mode() {
            if start.elapsed() >= cfg.iteration_time() {
                break;
            }
        } else if start.elapsed() >= Duration::from_secs(cfg.timeout_seconds as u64) {
            did_fail = true;
            println!("Iteration timed out");
            break;
        }
    }

    // Stop fuzzing this pid, then tear the process down.
    shared.script_pid.store(0, Ordering::SeqCst);
    while child.try_wait().context("failed to poll target")?.is_none() {
        let _ = child.kill();
        println!("Killing process");
        thread::sleep(POLL_INTERVAL);
    }

    Ok(IterationResult {
        duration_seconds: iteration_start.elapsed().as_secs_f64(),
        did_fail,
    })
}

// Run the configured error command and report whether it succeeded. An empty
// command never signals an error, matching the Java version.
fn does_error_script_succeed(cfg: &Config) -> bool {
    if cfg.error_command.is_empty() {
        return false;
    }
    match Command::new("/bin/sh")
        .arg("-c")
        .arg(&cfg.error_command)
        .status()
    {
        Ok(status) => status.success(),
        Err(e) => {
            eprintln!("error command failed to run: {e}");
            false
        }
    }
}

fn print_iteration_stats(durations: &[f64]) {
    let count = durations.len();
    if count == 0 {
        return;
    }

    let sum: f64 = durations.iter().sum();
    let mean = sum / count as f64;
    let min = durations.iter().cloned().fold(f64::MAX, f64::min);
    let max = durations.iter().cloned().fold(f64::MIN, f64::max);

    let sum_squared_diff: f64 = durations.iter().map(|d| (d - mean).powi(2)).sum();
    let std_dev = (sum_squared_diff / count as f64).sqrt();

    println!();
    println!("Iteration Count: {count}");
    println!("Iteration Duration: mean={mean:.1}s+-{std_dev:.1}s,min={min:.1}s,max={max:.1}s");
}
