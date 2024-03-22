#!/bin/bash

GIT_ROOT_DIR=$(git rev-parse --show-toplevel)
LIB_PATH=${GIT_ROOT_DIR?}/libtime.so

# Create temporary file
FILE=$(mktemp "/tmp/$(basename "$0").XXXXX") || exit 1
trap 'rm -f ${FILE?}' EXIT

# Measure latencies of `read()` calls
echo "Measuring latencies of curl's \`recv()\` function calls..."
SYMBOL=recv LD_PRELOAD=${LIB_PATH?} OUTPUT=${FILE?} curl -v --progress-bar --no-keepalive --max-time 10 -o /dev/null http://ipv4.download.thinkbroadband.com/1GB.zip 2> /dev/null
#SYMBOL=fwrite LD_PRELOAD=${LIB_PATH?} OUTPUT=${FILE?} curl -v --progress-bar --no-keepalive --max-time 10 -o /dev/null http://ipv4.download.thinkbroadband.com/1GB.zip 2> /dev/null

# Calculate latency statistics
echo "Calculating latency statistics..."
"${GIT_ROOT_DIR?}"/scripts/percentiles.sh "${FILE?}"
