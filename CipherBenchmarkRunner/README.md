# CipherBenchmarkRunner

This benchmark program is designed to measure the time performance of a specific cipher implementation. It appends to a .csv data file according to the following columns:

- DEVICE: storage device
- ARCH: system architecture
- LIB: encryption library
- ALG: algorithm
- KEY_LEN: key bit length
- BLOCK_MODE: encryption mode
- BLOCK_LEN: block bit length
- FILE_BYTES: input file length
- CIPHERTEXT_BYTES: output file length
- ENCRYPT_T: encryption time
- DECRYPT_T: decryption time
- ENCRYPT_IO_T: encryption I/O time
- DECRYPT_IO_T: decryption I/O time

*Note: times are in nanoseconds*

Usage:

    cipher-benchmark-runner <mode> <cipher> <input file> <output file> <key file> <results file> <error log file> <storage device>

    - mode: `/E (encrypt) or /D (decrypt)`
    - cipher: see `data/algorithm-list.txt` for implementation names
    - input file: plaintext filename
    - output file: ciphertext filename
    - key file: file containing encryption key data
    - results file: output csv file
    - error log file: output log
    - storage device: device name (for csv column data only)

### Known bugs:

- When using WolfCrypt factory interface, generated ciphertext size is not reported correctly. The reported length is always equal or larger to the actual encrypted data size.