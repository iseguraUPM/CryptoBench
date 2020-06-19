#!/bin/sh

if [ "$(id -u)" != "0" ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

currentMillis() {
  local ms=$(date +%s%3N)
  echo $((ms))
}

dropCaches() {
  sync; echo 3 > /proc/sys/vm/drop_caches
}

if [ "$#" -ne 6 ]; then
  echo "Usage: $0 <benchmark program> <prefix> <storage device> <min test size> <max test size> <no iterations>" >&2
  exit 1
fi

if ! [ -f combine-benchmarks.py ]; then
    echo "Missing script: combine-benchmarks.py" >&2
    exit 1
fi

if ! [ -f generate-random-binary.sh ]; then
    echo "Missing script: generate-random-binary.sh" >&2
    exit 1
fi

if ! [ -f algorithm-list.txt ]; then
    echo "Missing algorithm list file: algorithm-list.txt" >&2
    exit 1
fi

program=$1
prefix=$2
device=$3
minsize=$4
maxsize=$5
repeat=$6
enc_result_file="benchmark_$(date +%Y-%m-%d-%H-%M-%S)_enc.csv"
dec_result_file="benchmark_$(date +%Y-%m-%d-%H-%M-%S)_dec.csv"
final_result_file="benchmark_$(date +%Y-%m-%d-%H-%M-%S).csv"
error_file="err_benchmark_$(date +%Y-%m-%d-%H-%M-%S).log"

plaintextdir="${prefix}plaintext/"
if ! [ -d $plaintextdir ]; then
  mkdir "$plaintextdir"
  sh generate-random-binary.sh "$minsize" "$maxsize" "$plaintextdir" "bytes.bin"
fi

echo "DEVICE,ARCH,LIB,ALG,KEY_LEN,BLOCK_MODE,BLOCK_LEN,FILE_BYTES,CIPHERTEXT_BYTES,ENCRYPT_T,DECRYPT_T,ENCRYPT_IO_T,DECRYPT_IO_T" > "$enc_result_file"
echo "DEVICE,ARCH,LIB,ALG,KEY_LEN,BLOCK_MODE,BLOCK_LEN,FILE_BYTES,CIPHERTEXT_BYTES,ENCRYPT_T,DECRYPT_T,ENCRYPT_IO_T,DECRYPT_IO_T" > "$dec_result_file"

dropCaches

now_global=$(currentMillis)
echo "Running benchmark..."

for i in $(seq 1 $repeat); do
  echo "Iteration: $i"
  now=$(currentMillis)
  while IFS="" read -r cipher; do
    for plaintext in "$plaintextdir"*bytes.bin; do
      "$program" "/E" "$cipher" "$plaintext" "${prefix}output.enc" "key.bin" "$enc_result_file" "$error_file" "$device"
      dropCaches
      "$program" "/D" "$cipher" "${prefix}output.enc" "${prefix}recovered.bin" "key.bin" "$dec_result_file" "$error_file" "$device"
      dropCaches
    done
  done < algorithm-list.txt
  then=$(currentMillis)
  echo "Finished iteration $i .. Elapsed: $(($then-$now)) ms"
  
done

then_global=$(currentMillis)
echo "Finished all iterations! Elapsed: $(($then_global-$now_global)) ms"


echo "Merging files..."
python combine-benchmarks.py "$enc_result_file" "$dec_result_file" "$final_result_file"
echo "Done!"