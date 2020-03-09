# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)
project(wolfssl)

# Add preprocessor defines to CFLAGS
add_definitions(-DHAVE_AESCCM -DHAVE_AESGCM -DHAVE_CAMELLIA)

# set wolfSSL location as environment variable, change if needed
set(wolfssl_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib)

# Add wolfSSL library source files, to be compiled as SHARED library
add_library(wolfssl STATIC
        ${wolfssl_DIR}/wolfcrypt/src/aes.c
        ${wolfssl_DIR}/wolfcrypt/src/arc4.c
        ${wolfssl_DIR}/wolfcrypt/src/asm.c
        ${wolfssl_DIR}/wolfcrypt/src/asn.c
        ${wolfssl_DIR}/wolfcrypt/src/blake2b.c
        ${wolfssl_DIR}/wolfcrypt/src/camellia.c
        ${wolfssl_DIR}/wolfcrypt/src/chacha.c
        ${wolfssl_DIR}/wolfcrypt/src/chacha20_poly1305.c
        ${wolfssl_DIR}/wolfcrypt/src/cmac.c
        ${wolfssl_DIR}/wolfcrypt/src/coding.c
        ${wolfssl_DIR}/wolfcrypt/src/compress.c
        ${wolfssl_DIR}/wolfcrypt/src/cpuid.c
        ${wolfssl_DIR}/wolfcrypt/src/curve25519.c
        ${wolfssl_DIR}/wolfcrypt/src/des3.c
        ${wolfssl_DIR}/wolfcrypt/src/dh.c
        ${wolfssl_DIR}/wolfcrypt/src/dsa.c
        ${wolfssl_DIR}/wolfcrypt/src/ecc.c
        ${wolfssl_DIR}/wolfcrypt/src/ecc_fp.c
        ${wolfssl_DIR}/wolfcrypt/src/ed25519.c
        ${wolfssl_DIR}/wolfcrypt/src/error.c
        ${wolfssl_DIR}/wolfcrypt/src/fe_low_mem.c
        ${wolfssl_DIR}/wolfcrypt/src/fe_operations.c
        ${wolfssl_DIR}/wolfcrypt/src/ge_low_mem.c
        ${wolfssl_DIR}/wolfcrypt/src/ge_operations.c
        ${wolfssl_DIR}/wolfcrypt/src/hash.c
        ${wolfssl_DIR}/wolfcrypt/src/hc128.c
        ${wolfssl_DIR}/wolfcrypt/src/hmac.c
        ${wolfssl_DIR}/wolfcrypt/src/idea.c
        ${wolfssl_DIR}/wolfcrypt/src/integer.c
        ${wolfssl_DIR}/wolfcrypt/src/logging.c
        ${wolfssl_DIR}/wolfcrypt/src/md2.c
        ${wolfssl_DIR}/wolfcrypt/src/md4.c
        ${wolfssl_DIR}/wolfcrypt/src/md5.c
        ${wolfssl_DIR}/wolfcrypt/src/memory.c
        ${wolfssl_DIR}/wolfcrypt/src/pkcs12.c
        ${wolfssl_DIR}/wolfcrypt/src/pkcs7.c
        ${wolfssl_DIR}/wolfcrypt/src/poly1305.c
        ${wolfssl_DIR}/wolfcrypt/src/pwdbased.c
        ${wolfssl_DIR}/wolfcrypt/src/rabbit.c
        ${wolfssl_DIR}/wolfcrypt/src/random.c
        ${wolfssl_DIR}/wolfcrypt/src/ripemd.c
        ${wolfssl_DIR}/wolfcrypt/src/rsa.c
        ${wolfssl_DIR}/wolfcrypt/src/sha.c
        ${wolfssl_DIR}/wolfcrypt/src/sha256.c
        ${wolfssl_DIR}/wolfcrypt/src/sha3.c
        ${wolfssl_DIR}/wolfcrypt/src/sha512.c
        ${wolfssl_DIR}/wolfcrypt/src/signature.c
        ${wolfssl_DIR}/wolfcrypt/src/srp.c
        ${wolfssl_DIR}/wolfcrypt/src/tfm.c
        ${wolfssl_DIR}/wolfcrypt/src/wc_encrypt.c
        ${wolfssl_DIR}/wolfcrypt/src/wc_port.c
        ${wolfssl_DIR}/wolfcrypt/src/wolfevent.c
        ${wolfssl_DIR}/wolfcrypt/src/wolfmath.c
        ${wolfssl_DIR}/src/crl.c
        ${wolfssl_DIR}/src/internal.c
        ${wolfssl_DIR}/src/wolfio.c
        ${wolfssl_DIR}/src/keys.c
        ${wolfssl_DIR}/src/ocsp.c
        ${wolfssl_DIR}/src/sniffer.c
        ${wolfssl_DIR}/src/ssl.c
        ${wolfssl_DIR}/src/tls.c
        ${wolfssl_DIR}/src/tls13.c
        )


# Add header directories to include paths
target_include_directories(
        wolfssl
        PUBLIC
        ${wolfssl_DIR}
)