#!/bin/sh
# Convenience wrapper that runs the release binary as root, since attaching a
# sched_ext scheduler and reading the trace pipe both require privileges.
#
# Build first with "cargo build --release", then for example:
#   ./scheduler.sh samples/run_queue.sh --log

SCRIPT_DIR="$(dirname "$0")"
BIN="$SCRIPT_DIR/target/release/concurrency-fuzz-scheduler"

if [ ! -x "$BIN" ]; then
	echo "Binary not found at $BIN. Build it with: cargo build --release" >&2
	exit 1
fi

exec sudo "$BIN" "$@"
