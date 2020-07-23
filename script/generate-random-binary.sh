#!/bin/sh

usage() {
  echo "Usage: $0 <min bytes> <max bytes> <prefix> <suffix>" >&2
}

isNumber() {
  echo "$1" | grep -q "^[0-9]*$" && echo 1 || echo 0
}

if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
  echo "Random Binary File Generator"
  echo ""
  echo "    Generate random binary files within range. Files will be generated in powers of 2."
  echo "    Example: $ $0 2 128 random.bin"
  echo "      will generate random files of 2, 4, 8, 16, 32, 64 and 128 bytes."
  echo "      with names 2_random.bin, 4_random.bin, etc."
  echo ""
  usage
  exit 0
fi

if [ "$#" -ne 4 ]; then
  usage
  exit 1
fi

testA=$(isNumber "$1")
testB=$(isNumber "$2")

if [ $((testA)) -eq 0 ] || [ $((testB)) -eq 0 ]; then
  echo "First two arguments must be numeric" >&2
  usage
  exit 1
fi

if [ $(($1)) -le 0 ] || [ $(($2)) -le 0 ]; then
  echo "File size must be greater than 0" >&2
  usage
  exit 1
fi

if [ $(($1)) -gt $(($2)) ]; then
  echo "<min bytes> must be less than <max bytes>" >&2
  usage
  exit 1
fi

count=0
size=$(($1))
while [ $((size)) -le $(($2)) ]; do
  #dd if=/dev/urandom of="${3}${size}_${4}" bs=$size count=1 > /dev/null 2>&1
  head -c $size </dev/urandom > "${3}${size}_${4}"
  size=$((size*2))
  count=$((count+1))
done

echo "Generated $count binary file(s)"
