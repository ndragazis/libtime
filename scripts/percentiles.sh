#!/bin/sh
#
# This is a script for calculating latency metrics. It parses the
# measurements from a log file (provided as a command-line argument) and
# it calculates the minimum, maximum, average values and the
# (50th, 90th, 99th) percentiles.
#
# This script has been written to assist the parsing of log messages
# produced by libtime.
#
#
# Example usage:
#
# $ ./scripts/percentiles.sh /path/to/logfile.log
#
# Min: 835
# Max: 224928
# Avg: 6024.59
#
# 50th, 90th and 99th percentiles for 2097204 data points:
#
# 5216
# 8922
# 19232
#
#
# Based on:
# https://gist.github.com/stig/c7a13879534126fbf56c
#

# Exit immediately on error
set -e

# Create temporary file
FILE=$(mktemp /tmp/$(basename $0).XXXXX) || exit 1
trap "rm -f $FILE" EXIT

# Parse latencies from log file and sort entries
awk '{if ($NF == "nsec") print $(NF-1)}' $* | sort -n > $FILE

# Count number of data points
N=$(wc -l $FILE | awk '{print $1}')

# Calculate Min, Max, Avg
Min=$(awk '{if (NR == 1) print; exit}' $FILE)
Max=$(awk 'END{print}' $FILE)
Avg=$(awk 'BEGIN{sum = 0;count = 0;}{sum += $(NF); count++;}END{print sum / count;}' $FILE)

# Calculate line numbers for each percentile we're interested in
P50=$(dc -e "$N 2 / p")
P90=$(dc -e "$N 9 * 10 / p")
P99=$(dc -e "$N 99 * 100 / p")

#Print results

echo ""
echo "Min: "$Min
echo "Max: "$Max
echo "Avg: "$Avg

echo ""
echo "50th, 90th and 99th percentiles for $N data points:"

echo ""
awk "FNR==$P50 || FNR==$P90 || FNR==$P99" $FILE
echo ""
