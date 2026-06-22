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

In-kernel BPF design
--------------------

The original is written in Java with [hello-ebpf](https://github.com/parttimenerd/hello-ebpf),
which compiles the scheduler from Java down to a sched_ext BPF program. There the run/sleep
policy runs *inside the kernel* as BPF.

This port follows the same in-kernel design: the run/sleep policy is a sched_ext BPF program
written in C in [`src/bpf/main.bpf.c`](src/bpf/main.bpf.c), and the Rust in this repository is
only a thin loader plus the campaign supervisor. **The scheduling decision never leaves the
kernel.**

That choice is deliberate and is the point of this branch. The motivation is reproducibility
under a deterministic hypervisor (Bedrock): if the decision ran in a user-space process, its
own nondeterminism (thread interleavings, hash-map iteration order, wall-clock timing) would
leak into the schedule and a run could not be replayed from a seed. With the policy in the
kernel, the only inputs are a seeded PRNG and the (deterministic, under Bedrock) guest clock
and task-wakeup order, so the same seed reproduces the same schedule.

An earlier variant of this project put the policy in Rust user space on top of
[scx_rustland_core](https://crates.io/crates/scx_rustland_core), which kept the repository
free of C but routed every scheduling decision through a user/kernel round trip. That variant
lives on the `main` branch; this branch trades "no C" for "no user space in the decision path".

> Why not write the in-kernel scheduler in Rust too? As of mid-2026 the Rust eBPF toolchain
> (aya) does not yet support sched_ext `struct_ops`, and rustc cannot yet emit the BTF/CO-RE
> relocations needed to read `task_struct` fields portably. So the in-kernel part is C, which
> is also what every scheduler in [sched-ext/scx](https://github.com/sched-ext/scx) does.

### What changed from the original, and why it still behaves the same

This is a re-architecture, not a line-for-line translation. The original keeps a "sleeping"
task off the CPU by leaving it parked in the kernel dispatch queue and skipping it. Here every
queued task lives in one shared dispatch queue ordered by the time at which it next becomes
eligible to run; a sleeping task is inserted with a future eligibility time, so it stays
queued but `dispatch()` refuses to run it until its time arrives. A periodic timer kicks the
CPUs so eligibility is re-checked even when the system would otherwise idle. The observable
effect (threads getting stopped and started at random) is the same.

Trade-offs of the in-kernel design:

- **Pro: no user space in the decision path**, which is what makes seed-based replay possible
  under a deterministic hypervisor.
- **Pro: the decision is cheap.** No user/kernel round trip per scheduling event.
- **Con: the repository now contains C** ([`src/bpf/main.bpf.c`](src/bpf/main.bpf.c) and
  [`src/bpf/intf.h`](src/bpf/intf.h)) that you maintain against the sched_ext kfunc ABI.
- **Con: it tracks the sched_ext ABI.** The `scx_utils` and `libbpf-rs` versions are pinned
  and must match your kernel; a kernel upgrade may require a bump.

How it works
------------

Two threads cooperate:

- The **scheduler** is the BPF program in [`src/bpf/main.bpf.c`](src/bpf/main.bpf.c). For every
  task that belongs to the fuzzed process it drives a small state machine: run for a random
  time from `--run`, then sleep for a random time from `--sleep`, and so on. Tasks unrelated to
  the target run normally with a fixed system slice. Relatedness is determined in-kernel by
  reading the task's thread group and parent from `task_struct`, replacing the original
  task_struct walk. The Rust **loader** ([`src/fuzz.rs`](src/fuzz.rs)) attaches it, pushes the
  config and `--seed` in, tells it which pid to fuzz, and drains a ring buffer of run/sleep
  events to print the log.
- The **supervisor thread** ([`src/supervisor.rs`](src/supervisor.rs)) launches the target,
  tells the scheduler which pid to fuzz, and restarts the target each iteration until it
  crashes (non-zero exit), a custom error command succeeds, or a timeout fires.

Requirements
------------

- A Linux kernel with sched_ext, version 6.12 or later (the original recommends 6.13+), built
  with `CONFIG_SCHED_CLASS_EXT=y` and `CONFIG_DEBUG_INFO_BTF=y`.
- The BPF build toolchain used to compile the in-kernel scheduler: `clang`, `llvm-strip`,
  `bpftool`, `libbpf` development headers, and `pkg-config`.
- A Rust toolchain (stable).
- Root privileges to run (attaching a sched_ext scheduler requires them).

Build
-----

```sh
cargo build --release
```

At build time [`build.rs`](build.rs) runs `scx_utils`'s `BpfBuilder`, which generates
`vmlinux.h`, compiles [`src/bpf/main.bpf.c`](src/bpf/main.bpf.c) with `clang`, and produces the
libbpf-rs skeleton plus the bindings for the structs shared in
[`src/bpf/intf.h`](src/bpf/intf.h).

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
      --seed <SEED>              Seed for the in-kernel PRNG; same seed reproduces the schedule
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
$ timeout 30 samples/run_queue.sh; echo "exit: $?"
exit: 124  # terminated due to timeout
```

Run under the fuzzing scheduler, the consumer thread gets starved long enough for a buried
item to go stale, and the program crashes:

```sh
$ ./scheduler.sh samples/run_queue.sh --log --seed 0x1337
WARNING: this is an experimental sched_ext scheduler proof of concept. It schedules the whole system while attached; do not run it on a machine you care about.
sleep range: 10.000ms - 2.000s, run range: 1.000ms - 100.000ms, system slice: 5.000ms, slice: 5.000ms, seed: 0x1337
libbpf: struct_ops fifo_fuzz_ops: member sub_attach not found in kernel, skipping it as it's set to zero
libbpf: struct_ops fifo_fuzz_ops: member sub_detach not found in kernel, skipping it as it's set to zero
libbpf: struct_ops fifo_fuzz_ops: member sub_cgroup_id not found in kernel, skipping it as it's set to zero
libbpf: map 'fifo_fuzz_ops': BPF map skeleton link is uninitialized
Iteration
[ 0.110| 0.010] queue is running for 57ms
[ 0.120| 0.020] queue is running for 85ms
[ 0.171| 0.071] queue is sleeping for 780ms
[ 0.220| 0.120] queue is sleeping for 105ms
[ 0.346| 0.246] queue is running for 53ms
[ 0.406| 0.306] queue is sleeping for 113ms
[ 0.533| 0.433] queue is running for 82ms
[ 0.634| 0.534] queue is sleeping for 529ms
[ 0.953| 0.853] queue is running for 2ms
[ 0.963| 0.863] queue is sleeping for 1218ms
[ 1.183| 1.083] queue is running for 47ms
[ 1.243| 1.143] queue is sleeping for 155ms
[ 1.420| 1.320] queue is running for 97ms
[ 1.520| 1.420] queue is sleeping for 1999ms
[ 2.192| 2.092] queue is running for 43ms
Item is invalid! age 1070ms
[ 2.233| 2.132] queue is running for 81ms

Iteration Count: 1
Iteration Duration: mean=2.3s+-0.0s,min=2.3s,max=2.3s

Program failed after 2.303
EXIT: unregistered from user space
```

Note that the second time the scheduler is run with the same seed, the sleep
durations are reproduced, but the overall run is not: the target's threads share
one in-kernel PRNG, and on a multi-core host the order in which they consume it
(and their real-time progress) is not deterministic, so the runs diverge. Under
Bedrock a single vCPU and a deterministic clock fix that order, so the same seed
should reproduce the whole run.

```sh
$ ./scheduler.sh samples/run_queue.sh --log --seed 0x1337
WARNING: this is an experimental sched_ext scheduler proof of concept. It schedules the whole system while attached; do not run it on a machine you care about.
sleep range: 10.000ms - 2.000s, run range: 1.000ms - 100.000ms, system slice: 5.000ms, slice: 5.000ms, seed: 0x1337
libbpf: struct_ops fifo_fuzz_ops: member sub_attach not found in kernel, skipping it as it's set to zero
libbpf: struct_ops fifo_fuzz_ops: member sub_detach not found in kernel, skipping it as it's set to zero
libbpf: struct_ops fifo_fuzz_ops: member sub_cgroup_id not found in kernel, skipping it as it's set to zero
libbpf: map 'fifo_fuzz_ops': BPF map skeleton link is uninitialized
Iteration
[ 0.101| 0.001] queue is running for 57ms
[ 0.102| 0.001] queue is running for 85ms
[ 0.162| 0.061] queue is sleeping for 780ms
[ 0.192| 0.092] queue is sleeping for 105ms
[ 0.308| 0.208] queue is running for 53ms
[ 0.368| 0.268] queue is sleeping for 113ms
[ 0.493| 0.392] queue is running for 82ms
[ 0.583| 0.483] queue is sleeping for 529ms
[ 0.959| 0.859] queue is running for 2ms
[ 0.979| 0.879] queue is sleeping for 1218ms
[ 1.123| 1.022] queue is running for 47ms
[ 1.173| 1.073] queue is sleeping for 155ms
[ 1.332| 1.232] queue is running for 97ms
[ 1.433| 1.333] queue is sleeping for 1999ms
[ 2.216| 2.116] queue is running for 43ms
[ 2.277| 2.176] queue is sleeping for 527ms
[ 2.822| 2.722] queue is running for 81ms
[ 2.923| 2.822] queue is sleeping for 1987ms
[ 3.443| 3.343] queue is running for 78ms
[ 3.524| 3.423] queue is sleeping for 1556ms
[ 4.930| 4.830] queue is running for 86ms
[ 5.030| 4.930] queue is sleeping for 1578ms
[ 5.091| 4.991] queue is running for 60ms
[ 5.152| 5.052] queue is sleeping for 1229ms
Item is invalid! age 1244ms
[ 5.352| 5.252] queue is sleeping for 401ms

Iteration Count: 1
Iteration Duration: mean=5.4s+-0.0s,min=5.4s,max=5.4s

Program failed after 5.406
EXIT: unregistered from user space
```

License
=======
GPLv2
