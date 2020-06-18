#!/bin/sh

if [ "$(id -u)" != "0" ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <benchmark program> <no. repetition>" >&2
  exit 1
fi

script=run-cryptobench.sh
if ! [ -f $script ]; then
    echo "Missing script: $script" >&2
    exit 1
fi

program=$1
repeat=$2

for i in $(seq 1 $repeat); do
    echo "Iteration: $i"
    sh "$script" "$program"
    echo ""
done