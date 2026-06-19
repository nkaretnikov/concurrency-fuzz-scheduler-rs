#!/bin/sh
# Run the producer-consumer sample, building it first if needed.
BASEDIR=$(dirname "$0")

if [ ! -x "$BASEDIR/queue" ]; then
	"$BASEDIR/build_queue.sh" || exit 1
fi

exec "$BASEDIR/queue" "$@"
