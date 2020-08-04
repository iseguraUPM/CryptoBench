import pandas as pd
import sys
import math

def next_power_of_2(x):
    return 1 if x == 0 else 2**math.ceil(math.log2(x))


if len(sys.argv) != 4:
    print("Invalid usage.")
    print("Usage: python " + sys.argv[0] + " <benchmark_file> <engine_benchmark_file> <output file>")


benchmark_df = pd.read_csv(sys.argv[1])
eng_benchmark_df = pd.read_csv(sys.argv[2])
result_df = pd.DataFrame(columns=['FILE_BYTES', 'SEC_LEVEL', 'ENGINE_T', 'FRAGMENTS_T'])
result_file = sys.argv[3]


for _, row in eng_benchmark_df.iterrows():
    if row['FRAGMENTS'] != '':
        fragments = row['FRAGMENTS'].split(":")
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
    result_df = result_df.append({'FILE_BYTES': row['FILE_BYTES'], 'SEC_LEVEL': row['SEC_LEVEL'], 'ENGINE_T': row['TOTAL_T'], 'FRAGMENTS_T': fragments_sum}, ignore_index=True)


result_df.to_csv(result_file, index=False)


