Concurrency Fuzz Scheduler (Rust port)
======================================

__Disclaimer: This is a proof of concept and highly experimental. Use at your own risk.__

A Rust port of [parttimenerd/concurrency-fuzz-scheduler](https://github.com/parttimenerd/concurrency-fuzz-scheduler),
a scheduler that creates random scheduling edge cases to fuzz concurrent applications. It
deliberately stops and starts an application's threads at random, in the kernel, so the
application cannot defend against it the way it could against POSIX stop and start signals.
That manufactures the rare thread interleavings that surface concurrency bugs.

It is the code for the FOSDEM'25 talk
[Concurrency Testing using Custom Linux Schedulers](https://fosdem.org/2025/schedule/event/fosdem-2025-4489-concurrency-testing-using-custom-linux-schedulers/).
For background on sched_ext, see the [LWN article](https://lwn.net/SubscriberLink/1007689/922423e440f5e68a/).

This repository is 100% Rust
----------------------------

The original is written in Java with [hello-ebpf](https://github.com/parttimenerd/hello-ebpf),
which compiles the scheduler from Java down to a sched_ext BPF program. There the run/sleep
policy runs *inside the kernel* as BPF.

This port is **entirely Rust**, with **no C in the repository**. It achieves that by being a
user-space scheduler built on [scx_rustland_core](https://crates.io/crates/scx_rustland_core):

- The scheduling policy (the random run/sleep state machine, per-task slices, the
  "is this task part of the target" decision, the logging) is plain Rust in
  [`src/fuzz.rs`](src/fuzz.rs).
- `scx_rustland_core` provides a generic sched_ext BPF backend that forwards every runnable
  task up to user space and dispatches the tasks we hand back. That backend is C, but it
  lives inside the dependency crate; we never write or maintain any C.

### What changed from the original, and why it still behaves the same

This is a re-architecture, not a line-for-line translation. The original keeps a "sleeping"
task off the CPU by leaving it parked in the kernel dispatch queue and skipping it. Here the
equivalent is: when a task should sleep, user space simply receives it from the backend and
declines to dispatch it, holding it until its random sleep timer expires, then dispatches it
again. The observable effect (threads getting stopped and started at random) is identical.

Trade-offs of the user-space design:

- **Pro: the whole project is Rust** and the policy is easy to read and modify.
- **Pro: logging is direct.** Because the policy runs in user space, the run/sleep log lines
  are printed directly instead of being routed through the kernel trace pipe.
- **Con: a scheduling decision is a user/kernel round trip**, so this is slower than an
  in-kernel scheduler. For a fuzzer that deliberately injects millisecond-scale delays this
  overhead is irrelevant, but it is the reason real schedulers keep hot paths in BPF.
- **Con: it tracks the sched_ext ABI.** The `scx_rustland_core`, `scx_utils` and `libbpf-rs`
  versions are pinned and must match your kernel; a kernel upgrade may require a bump.

If you instead want the in-kernel design of the original (a `*.bpf.c` plus a thin Rust
loader), that is a different, equally valid shape; this repository chose the all-Rust route.

How it works
------------

Two threads cooperate:

- The **scheduler thread** ([`src/fuzz.rs`](src/fuzz.rs)) runs the policy. For every task
  that belongs to the fuzzed process it drives a small state machine: run for a random time
  from `--run`, then sleep for a random time from `--sleep`, and so on. Tasks unrelated to
  the target are dispatched immediately with a fixed system slice. Relatedness is determined
  by reading `/proc` for the task's thread group and parent, mirroring the original's
  task_struct walk.
- The **supervisor thread** ([`src/supervisor.rs`](src/supervisor.rs)) launches the target,
  tells the scheduler which pid to fuzz, and restarts the target each iteration until it
  crashes (non-zero exit), a custom error command succeeds, or a timeout fires.

Requirements
------------

- A Linux kernel with sched_ext, version 6.12 or later (the original recommends 6.13+).
- The BPF build toolchain used to compile the bundled backend: `clang`, `llvm-strip`,
  `bpftool`, `libbpf` development headers, and `pkg-config`.
- A Rust toolchain (stable).
- Root privileges to run (attaching a sched_ext scheduler requires them).

Build
-----

```sh
cargo build --release
```

At build time `scx_rustland_core`'s `RustLandBuilder` unpacks its BPF backend, compiles it,
generates `vmlinux.h`, and produces the libbpf-rs skeleton. The only files you maintain are
Rust.

Usage
-----

```
Usage: scheduler.sh [OPTIONS] <SCRIPT>

Arguments:
  <SCRIPT>  Script or command to execute

Options:
  -s, --sleep <RANGE>            Range of sleep lengths [default: 10ms,2000ms]
  -r, --run <RANGE>              Range of running time lengths [default: 1ms,100ms]
      --system-slice <DURATION>  Time slice for all non-script tasks [default: 5ms]
      --slice <DURATION>         Time slice for the script [default: 5ms]
  -e, --error-command <CMD>      Command to run on error, default checks exit code != 0
  -i, --iteration-time <DUR>     Time to run the script before restarting [default: 100s]
  -d, --dont-scale-slice         Do not scale the slice by the number of waiting tasks
  -m, --max-iterations <N>       Maximum number of iterations [default: -1]
      --error-check-interval <D> Time between two error-command checks [default: 10s]
      --log                      Log the state changes
  -t, --timeout <SECONDS>        Per-iteration timeout, -1 disables it [default: -1]
  -h, --help                     Print help
  -V, --version                  Print version
```

Durations accept `ns`, `us`, `ms` and `s`, with fractions, for example `1.5s`. A range is
either `min,max` (such as `10ms,2000ms`) or a single value used for both ends.

The `scheduler.sh` wrapper runs the release binary under `sudo` for convenience:

```sh
./scheduler.sh samples/run_queue.sh --log
```

Example
-------

The sample [samples/queue.c](samples/queue.c) is a tiny producer-consumer program. The
producer appends a timestamped item every 20ms; the consumer removes one every 10ms and
crashes if it pulls an item older than one second. Run normally it does not crash:

```sh
samples/build_queue.sh
samples/run_queue.sh
```

Run under the fuzzing scheduler, the consumer thread gets starved long enough for a buried
item to go stale, and the program crashes:

```sh
./scheduler.sh samples/run_queue.sh --log
```

License
=======
GPLv2
