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

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <benchmark program>" >&2
  exit 1
fi

program=$1
output_file="benchmark_$(date +%Y-%m-%d-%H-%M-%S).csv"
error_file="err_benchmark_$(date +%Y-%m-%d-%H-%M-%S).log"

echo "DEVICE,ARCH,LIB,ALG,KEY_LEN,BLOCK_MODE,BLOCK_LEN,FILE_BYTES,CIPHERTEXT_BYTES,ENCRYPT_T,DECRYPT_T,ENCRYPT_IO_T,DECRYPT_IO_T" > "$output_file"

now=$(currentMillis)
echo "Running benchmark..."
dropCaches 
$program botan-AES-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches
$program botan-AES-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-SIV 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-128-XTS 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-SIV 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-192-XTS 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-SIV 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-AES-256-XTS 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-SIV 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-128-XTS 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-SIV 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-192-XTS 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-SIV 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-ARIA-256-XTS 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-BLOWFISH-448-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-SIV 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-128-XTS 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-SIV 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-192-XTS 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-SIV 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-CAMELLIA-256-XTS 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-SIV 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program botan-SEED-128-XTS 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-AES-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-ARIA-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-BLOWFISH-448-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-CAMELLIA-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program cryptopp-SEED-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-AES-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-BLOWFISH-448-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-CAMELLIA-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OCB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program gcrypt-SEED-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program libsodium-AES-256-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-128-XTS 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-AES-256-XTS 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-ARIA-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-192-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-256-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-BLOWFISH-448-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CBC 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-CFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-ECB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program openssl-SEED-128-OFB 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-128-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-192-GCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CCM 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-CTR 262144_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 1_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 2_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 4_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 8_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 16_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 32_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 64_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 128_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 256_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 512_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 1024_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 2048_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 4096_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 8192_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 16384_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 32768_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 65536_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 131072_bytes.bin key.bin "$output_file" "$error_file" 
dropCaches 
$program wolfcrypt-AES-256-GCM 262144_bytes.bin key.bin "$output_file" "$error_file"
dropCaches
then=$(currentMillis)
echo "Done! Elapsed: $(($then-$now)) ms"