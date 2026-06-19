#!/bin/sh
# Build the producer-consumer sample.
BASEDIR=$(dirname "$0")
make -C "$BASEDIR" queue
echo "queue compiled successfully. Run it via run_queue.sh"
