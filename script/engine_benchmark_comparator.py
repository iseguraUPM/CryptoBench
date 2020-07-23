import pandas as pd
import sys
import math

def next_power_of_2(x):
    return 1 if x == 0 else 2**math.ceil(math.log2(x))


if len(sys.argv) != 3:
    print("Invalid usage.")
    print("Usage: python " + sys.argv[0] + " <benchmark_file> <engine_benchmark_file>")


benchmark_df = pd.read_csv(sys.argv[1])
eng_benchmark_df = pd.read_csv(sys.argv[2], names=["Arch", "fragmentsInfo", "strategy", "input_size", "sec_level", "overall_time_nano", "decision_time_nano", "encrypt_time_nano", "decrypt_time_nano", "encrypt_io_time_nano", "decrypt_io_time_nano"])
result_df = pd.DataFrame(columns=['FileSize', 'SecLevel', 'EngineTime', 'FragmentsTime'])


for _, row in eng_benchmark_df.iterrows():
    fragments = row['fragmentsInfo'].split(":")
    fragments_sum = 0
    for fragment in fragments:
        if len(fragment) > 0:                               # Last fragment
            fragment_split = fragment.split("-")
            print(fragment_split)
            file_size = fragment_split[0]
            lib = fragment_split[1]
            alg = fragment_split[2]
            key_len = fragment_split[3]
            mode = fragment_split[4]

            filtered_df = benchmark_df[(benchmark_df['FILE_BYTES'] == next_power_of_2(int(file_size) - 1)) & (benchmark_df['LIB'] == lib) & (benchmark_df['ALG'] == alg) & (benchmark_df['KEY_LEN'] == int(key_len)) & (benchmark_df['BLOCK_MODE'] == mode)]
            benchmark_time = filtered_df['ENCRYPT_T'].max() + filtered_df['ENCRYPT_IO_T'].max()

            fragments_sum += benchmark_time
            print(benchmark_time)

    print ("----------")
    result_df = result_df.append({'FileSize': row['input_size'], 'SecLevel': row['sec_level'], 'EngineTime': row['overall_time_nano'], 'FragmentsTime': fragments_sum}, ignore_index=True)


result_df.to_csv("comparison.csv", index=False)


