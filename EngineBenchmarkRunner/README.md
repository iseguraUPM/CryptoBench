# EngineBenchmarkRunner

This benchmark program is designed to measure the time performance of the HEncrypt engine. It appends to a .csv data file according to the following columns:

- ARCH: system architecture
- FRAGMENTS: list of cipher use in fragments (separated by ':')
- STRATEGY: encryption strategy
- FILE_BYTES: input file length in bytes
- SEC_LEVEL: security level
- TOTAL_T: overall encryption time
- DECISION_T: engine decision time
- ENCRYPT_T: total encryption time
- DECRYPT_T: total decryption time
- ENCRYPT_IO_T: total encryption I/O time
- DECRYPT_IO_T: total decryption I/O time

*Note: times are in nanoseconds*

Usage:

    engine-benchmark-runner <input file> <key file> <system profile> <cipher seed> <results file> <error log file>

    - input file: plaintext filename
    - key file: file containing encryption key data
    - system profile: system status file
    - cipher seed: initial cipher performance data
    - results file: output csv file
    - error log file: output log

### System profile file format:

For each device:

`<device name> <device storage path> <device pace (nanosec. per byte)>`

Example:

    nvme /mnt/c/crypto/ 1
    ssd /mnt/g/crypto/ 2
    hdd1 /mnt/e/crypto/ 6
    hdd2 /mnt/d/crypto/ 11

### Cipher seed file format:

First a space separated list of the block sizes (descending order). Folling by lines for each cipher implementation:

`<complete cipher name> <security level> <list of per block performance time in nanoseons>` 

Example:

    512 256 128
    botan-ARIA-256-XTS 5 31695932 31815407 32696192
    botan-CAMELLIA-128-XTS 5 29859658 30461691 0
    botan-CAMELLIA-192-XTS 5 0 0 32771114 33724267 35806820
    botan-CAMELLIA-256-XTS 5 0 0 0

*Note: use `script/cipher-seed-generator.py` to generate this file from benchmark .csv data*