Samples for testing the fuzzer.

- `queue.c` is a producer-consumer program with a scheduling sensitive
  staleness bug. Build it with `build_queue.sh` and run it with `run_queue.sh`.
  It does not crash under a normal scheduler, but it does under the fuzzing
  scheduler.
