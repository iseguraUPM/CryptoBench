#!/bin/sh

clean_caches=0

if [ "$(id -u)" == "0" ]; then
  clean_caches=1
fi

currentMillis() {
  local ms=$(date +%s%3N)
  echo $((ms))
}

dropCaches() {
  if [ "$clean_caches" -eq 1 ]; then
    sync; echo 3 > /proc/sys/vm/drop_caches
  fi
}

if [ "$#" -ne 7 ]; then
  echo "Usage: $0 <benchmark program> <prefix> <key file> <system profile> <cipher seed> <min test size> <max test size>" >&2
  exit 1
fi

program=$1
prefix=$2
key_file=$3
system_profile=$4
cipher_seed=$5
minsize=$6
maxsize=$7
repeat=1
enc_result_file="benchmark_$(date +%Y-%m-%d-%H-%M-%S)_enc.csv"
final_result_file="benchmark_$(date +%Y-%m-%d-%H-%M-%S).csv"
error_file="err_benchmark_$(date +%Y-%m-%d-%H-%M-%S).log"

plaintextdir="${prefix}plaintext/"
if ! [ -d $plaintextdir ]; then
  mkdir "$plaintextdir"
  sh generate-random-binary.sh "$minsize" "$maxsize" "$plaintextdir" "bytes.bin"
fi

echo "ARCH,FRAGMENTS,STRATEGY,FILE_BYTES,SEC_LEVEL,TOTAL_T,DECISION_T,ENCRYPT_T,DECRYPT_T,ENCRYPT_IO_T,DECRYPT_IO_T" > "$enc_result_file"

dropCaches

now_global=$(currentMillis)
echo "Running benchmark..."

for i in $(seq 1 $repeat); do
  echo "Iteration: $i"
  now=$(currentMillis)
  while IFS="" read -r cipher; do
    for plaintext in "$plaintextdir"*bytes.bin; do
      "$program" "$plaintext" "$key_file" "$system_profile" "$cipher_seed" "$enc_result_file" "$error_file"
      dropCaches
    done
  done < algorithm-list.txt
  then=$(currentMillis)
  echo "Finished iteration $i .. Elapsed: $(($then-$now)) ms"
  
done

then_global=$(currentMillis)
echo "Finished all iterations! Elapsed: $(($then_global-$now_global)) ms"