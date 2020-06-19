#!/bin/sh

if [ "$(id -u)" != "0" ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

if [ "$#" -ne 4 ]; then
  echo "Usage: $0 <benchmark program> <prefix> <storage device> <no. repetition>" >&2
  exit 1
fi

script=run-cryptobench.sh
if ! [ -f $script ]; then
    echo "Missing script: $script" >&2
    exit 1
fi

program=$1
prefix=$2
device=$3
repeat=$4

for i in $(seq 1 $repeat); do
    echo "Iteration: $i"
    sh "$script" "$program" "$prefix" "$device"
    echo ""
done