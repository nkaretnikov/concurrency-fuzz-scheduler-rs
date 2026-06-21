// The fuzzing scheduling policy, running entirely in user space.
//
// This is the port of FIFOScheduler.java. In the original the run/sleep state
// machine executed inside a sched_ext BPF program in the kernel. Here the same
// logic runs in user space on top of scx_rustland_core: the BPF backend hands
// us every runnable task through dequeue_task(), and we decide whether to
// dispatch it now or hold it back to manufacture an erratic interleaving.
//
// A task that the original kept "sleeping" by leaving it in the kernel dispatch
// queue is, in this model, simply a task we received and chose not to dispatch
// yet. We park it in `held` and release it once its random sleep time elapses.

use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use libbpf_rs::OpenObject;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::UserExitInfo;

use crate::bpf::*;
use crate::diagram::{DiagramHelper, EventType};
use crate::{Config, Shared};

// Granularity at which the loop re-checks held tasks and avoids busy spinning
// when there is no other work. notify_complete() does not block, so without a
// small pause here the scheduler thread would spin a CPU at 100 percent.
const IDLE_TICK: Duration = Duration::from_millis(1);

#[derive(Clone, Copy, PartialEq, Eq)]
enum TaskState {
    Start,
    Running,
    Sleeping,
}

// Per task fuzzing state, keyed by pid. `deadline` is when the current state
// ends; it stands in for the original lastStopNs plus timeAllowedInState.
struct TaskContext {
    state: TaskState,
    deadline: Instant,
}

// Small deterministic-per-process PRNG, in the spirit of bpf_get_prandom_u32.
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    // Random number in the half open range [min, max), matching the arithmetic
    // of FIFOScheduler.randomInRange.
    fn range(&mut self, min: u64, max: u64) -> u64 {
        if min == max {
            return min;
        }
        let r = self.next_u64() as u32 as u64;
        min + (r.wrapping_mul(31)) % (max - min)
    }
}

pub struct FuzzScheduler<'a> {
    bpf: BpfScheduler<'a>,
    cfg: Config,
    shared: Arc<Shared>,

    contexts: HashMap<i32, TaskContext>,
    related_cache: HashMap<i32, bool>,
    held: HashMap<i32, QueuedTask>,

    rng: Rng,
    diagram: DiagramHelper,

    global_start: Instant,
    generation: u64,
    gen_start: Instant,
}

impl<'a> FuzzScheduler<'a> {
    pub fn init(
        open_object: &'a mut MaybeUninit<OpenObject>,
        cfg: Config,
        shared: Arc<Shared>,
    ) -> Result<Self> {
        let open_opts = LibbpfOpts::default();
        let bpf = BpfScheduler::init(
            open_object,
            open_opts.clone().into_bpf_open_opts(),
            0,            // exit_dump_len, 0 keeps the default
            false,        // partial, false schedules all tasks
            false,        // debug off
            true,         // let the backend use idle CPUs
            false,        // ignore NUMA locality
            cfg.slice_ns, // default slice for backend dispatches
            "fifo_fuzz",  // scx ops name
        )?;

        // Announce that the scheduler is attached so the supervisor may start
        // launching the target program.
        shared.attached.store(true, Ordering::SeqCst);

        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e3779b97f4a7c15);

        let now = Instant::now();
        Ok(Self {
            bpf,
            cfg,
            shared,
            contexts: HashMap::new(),
            related_cache: HashMap::new(),
            held: HashMap::new(),
            rng: Rng::new(seed),
            diagram: DiagramHelper::new(),
            global_start: now,
            generation: 0,
            gen_start: now,
        })
    }

    pub fn run(&mut self) -> Result<UserExitInfo> {
        while !self.bpf.exited() && !self.shared.done.load(Ordering::SeqCst) {
            self.dispatch_tasks();
        }
        // Return any tasks we were still holding so none are left stranded as
        // runnable-but-never-dispatched when we detach.
        self.flush_held();
        self.bpf.shutdown_and_report()
    }

    fn dispatch_tasks(&mut self) {
        self.sync_generation();

        let script_pid = self.shared.script_pid.load(Ordering::SeqCst);
        let nr_waiting = *self.bpf.nr_queued_mut();
        let now = Instant::now();
        let mut did_work = false;

        // Release any held tasks whose sleep time has elapsed.
        let wake: Vec<i32> = self
            .held
            .keys()
            .copied()
            .filter(|pid| self.contexts.get(pid).map_or(true, |c| now >= c.deadline))
            .collect();
        for pid in wake {
            if let Some(task) = self.held.remove(&pid) {
                self.begin_running(&task, now);
                self.dispatch(&task, nr_waiting, true);
                did_work = true;
            }
        }

        // Consume freshly queued tasks.
        while let Ok(Some(task)) = self.bpf.dequeue_task() {
            did_work = true;
            let related = script_pid != 0 && self.is_related(task.pid, script_pid);

            if related {
                if self.update_state(&task, now) {
                    self.dispatch(&task, nr_waiting, true);
                } else {
                    // Sleeping: park the task until its sleep time is up.
                    self.held.insert(task.pid, task);
                }
            } else {
                // Unrelated tasks are dispatched normally with the system slice
                // so the rest of the machine keeps moving.
                self.dispatch(&task, nr_waiting, false);
            }
        }

        // Hand control back to the backend and report how many tasks we still
        // hold so it knows user space has pending work.
        let pending = self.held.len() as u64;
        self.bpf.notify_complete(pending);

        if !did_work {
            thread::sleep(IDLE_TICK);
        }
    }

    // Advance the run/sleep state machine for a task and report whether it may
    // run now. Mirrors updateStateIfNeededAndReturnIfSchedulable.
    fn update_state(&mut self, task: &QueuedTask, now: Instant) -> bool {
        let state = self
            .contexts
            .get(&task.pid)
            .map(|c| (c.state, c.deadline))
            .unwrap_or((TaskState::Start, now));

        match state {
            (TaskState::Start, _) => {
                // First sight: flip a coin between starting to run or to sleep.
                if self.rng.range(0, 2) == 0 {
                    self.begin_sleeping(task, now);
                    false
                } else {
                    self.begin_running(task, now);
                    true
                }
            }
            (TaskState::Running, deadline) => {
                if now >= deadline {
                    self.begin_sleeping(task, now);
                    false
                } else {
                    true
                }
            }
            (TaskState::Sleeping, deadline) => {
                if now >= deadline {
                    self.begin_running(task, now);
                    true
                } else {
                    false
                }
            }
        }
    }

    fn begin_running(&mut self, task: &QueuedTask, now: Instant) {
        let duration_ns = self
            .rng
            .range(self.cfg.run_range.min_ns, self.cfg.run_range.max_ns);
        self.contexts.insert(
            task.pid,
            TaskContext {
                state: TaskState::Running,
                deadline: now + Duration::from_nanos(duration_ns),
            },
        );
        self.log_event(task, EventType::Running, duration_ns);
    }

    fn begin_sleeping(&mut self, task: &QueuedTask, now: Instant) {
        let duration_ns = self
            .rng
            .range(self.cfg.sleep_range.min_ns, self.cfg.sleep_range.max_ns);
        self.contexts.insert(
            task.pid,
            TaskContext {
                state: TaskState::Sleeping,
                deadline: now + Duration::from_nanos(duration_ns),
            },
        );
        self.log_event(task, EventType::Sleeping, duration_ns);
    }

    fn dispatch(&mut self, task: &QueuedTask, nr_waiting: u64, related: bool) {
        let mut slice = if related {
            self.cfg.slice_ns
        } else {
            self.cfg.system_slice_ns
        };
        if self.cfg.scale_slice {
            // Shrink the slice as the run queue grows, so more tasks get a turn.
            slice /= nr_waiting + 1;
        }

        let mut dispatched = DispatchedTask::new(task);
        let cpu = self.bpf.select_cpu(task.pid, task.cpu, task.flags);
        dispatched.cpu = if cpu >= 0 { cpu } else { RL_CPU_ANY };
        dispatched.slice_ns = slice;
        let _ = self.bpf.dispatch_task(&dispatched);
    }

    // Dispatch everything we are still holding, used on shutdown and when a new
    // iteration invalidates the old per task state.
    fn flush_held(&mut self) {
        let held: Vec<QueuedTask> = self.held.drain().map(|(_, task)| task).collect();
        for task in held {
            let mut dispatched = DispatchedTask::new(&task);
            let cpu = self.bpf.select_cpu(task.pid, task.cpu, task.flags);
            dispatched.cpu = if cpu >= 0 { cpu } else { RL_CPU_ANY };
            let _ = self.bpf.dispatch_task(&dispatched);
        }
    }

    // When the supervisor starts a new iteration it bumps the generation. Pids
    // get reused across processes, so drop all cached state to start fresh.
    fn sync_generation(&mut self) {
        let generation = self.shared.generation.load(Ordering::SeqCst);
        if generation != self.generation {
            self.flush_held();
            self.contexts.clear();
            self.related_cache.clear();
            self.generation = generation;
            self.gen_start = Instant::now();
        }
    }

    // Decide whether a task belongs to the fuzzed process and cache the answer.
    // The original walked task_struct in the kernel; here we read /proc, which
    // gives us the same tgid and parent information.
    fn is_related(&mut self, pid: i32, script_pid: i32) -> bool {
        if let Some(&cached) = self.related_cache.get(&pid) {
            return cached;
        }
        let related = compute_related(pid, script_pid);
        self.related_cache.insert(pid, related);
        related
    }

    fn log_event(&mut self, task: &QueuedTask, event_type: EventType, duration_ns: u64) {
        if !self.cfg.log {
            return;
        }
        let comm = task.comm_str();
        let millis = duration_ns / 1_000_000;
        let verb = match event_type {
            EventType::Running => "running",
            EventType::Sleeping => "sleeping",
        };
        let overall = self.global_start.elapsed().as_secs_f64();
        let iteration = self.gen_start.elapsed().as_secs_f64();
        self.diagram
            .record_event(overall, &comm, event_type, duration_ns as f64 / 1_000_000_000.0);
        println!("[{overall:6.3}|{iteration:6.3}] {comm} is {verb} for {millis}ms");
    }
}

// Read /proc to learn the task's thread group and parent, then apply the same
// relatedness rule as the original: related when the tgid is the script pid, or
// the parent pid or parent tgid is.
fn compute_related(pid: i32, script_pid: i32) -> bool {
    let Ok(proc) = procfs::process::Process::new(pid) else {
        return false;
    };
    let Ok(status) = proc.status() else {
        return false;
    };
    if status.tgid == script_pid {
        return true;
    }
    let ppid = status.ppid;
    if ppid == script_pid {
        return true;
    }
    if let Ok(parent) = procfs::process::Process::new(ppid) {
        if let Ok(parent_status) = parent.status() {
            if parent_status.tgid == script_pid {
                return true;
            }
        }
    }
    false
}
