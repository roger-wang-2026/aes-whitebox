#!/bin/sh
# Linux x86_64 PIN engine, with its own matching runtime libraries.
PIN_ROOT=${PIN_ROOT:-/experiment/tools/pin}
TRACER_SO=${TRACER_SO:-/experiment/tools/dca/Tracer/TracerPIN/obj-intel64/Tracer.so}
export LD_LIBRARY_PATH="$PIN_ROOT/extras/xed-intel64/lib:$PIN_ROOT/intel64/lib:$PIN_ROOT/intel64/runtime/pincrt"
exec "$PIN_ROOT/intel64/bin/pinbin" -t "$TRACER_SO" "$@"
