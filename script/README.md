# Script utilities

*Execute scripts for usage information*

Collection of scripts used for the project:

- `cipher-seed-generator.py`: Python script to generate engine input file
- `combine-benchmark.py`: Python script to combine encrypt decrypt cipher benchmark .csv files
- `detect-drive.sh`: Shell script to detect HDD or SSD type of storage drive
- `engine-benchmark-comparator-py`: Python script to compare individual encryption benchmark data to HEncrypt performance data
- `generate-random-binary.sh`: Shell script used to generate specified size range set of random files
- `pre_generator.py`: Some used python functions to modify the benchmark .csv file. Needed for `cipher-seed-generator.py`

### Benchmark runners

Recommended when running any of both benchmarks

- `run-cryptobench.sh`: Automated cipher benchmarking of different file sizes. Used to generate the large dataset of cipher performance data
- `run-engine-cryptobench`: Automated HEncrypt engine benchmarking of different file sizes