#!/bin/bash

GIT_ROOT_DIR=$(git rev-parse --show-toplevel)
LIB_PATH=${GIT_ROOT_DIR?}/libtime.so

# Create temporary file
FILE=$(mktemp "/tmp/$(basename "$0").XXXXX") || exit 1
trap 'rm -f ${FILE?}' EXIT

# Measure latencies of `read()` calls
echo "Measuring latencies of dd's \`read()\` function calls..."
LD_BIND_NOW=1 SYMBOL=write LD_PRELOAD=${LIB_PATH?} OUTPUT=${FILE?} dd if=/dev/urandom of=/dev/null bs=1MiB count=512 2>/dev/null
#LD_BIND_NOW=1 SYMBOL=read LD_PRELOAD=${LIB_PATH?} OUTPUT=/tmp/foo dd if=/dev/urandom of=/dev/null bs=1MiB count=512

# Calculate latency statistics
echo "Calculating latency statistics..."
"${GIT_ROOT_DIR?}"/scripts/percentiles.sh "${FILE?}"
