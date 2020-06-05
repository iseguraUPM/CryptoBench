import pandas as pd
import math

print("Processing...")

filename = "benchmark_2020-04-26.csv"
rounds_filename = "block_cipher_rounds.csv"
sec_coefficient_range = 5

benchmark_df = pd.read_csv(filename)
rounds_df = pd.read_csv(rounds_filename)


def add_sec_level():
    global benchmark_df
    benchmark_df = pd.merge(benchmark_df, rounds_df, on=['ALG', 'KEY_LEN', 'BLOCK_LEN'], how='left')

    # Calculate the security coefficient
    benchmark_df['SECURITY_COEFFICIENT'] = benchmark_df.apply(lambda row: (math.log2(row['KEY_LEN']) + math.log2(row['BLOCK_LEN'])) * row['ROUNDS'], axis=1)
    min_sec_coeff = benchmark_df['SECURITY_COEFFICIENT'].min()
    max_sec_coeff = benchmark_df['SECURITY_COEFFICIENT'].max()

    # Normalize the security coefficient
    benchmark_df['SECURITY_NORM'] = benchmark_df.apply(lambda row: (row['SECURITY_COEFFICIENT'] - min_sec_coeff) / (max_sec_coeff-min_sec_coeff), axis=1)

    # Copy to another dataframe to get unique order and normalize by that order. We then merge it back.
    sec_levels = pd.DataFrame(data=benchmark_df['SECURITY_NORM'].drop_duplicates().sort_values().reset_index())
    sec_levels['SECURITY_LEVEL'] = sec_levels.apply(lambda row: 1+round(row.name * (sec_coefficient_range-1)/sec_levels.shape[0]), axis=1)
    sec_levels = sec_levels[['SECURITY_LEVEL', 'SECURITY_NORM']]
    print(sec_levels)
    benchmark_df = pd.merge(benchmark_df, sec_levels, on=['SECURITY_NORM'], how='left')

    benchmark_df = benchmark_df[['LIB', 'ALG', 'KEY_LEN', 'BLOCK_MODE', 'FILE_BYTES', 'ENCRYPT_T', 'DECRYPT_T', 'SECURITY_LEVEL']]


def get_winners(df, grouping_cols):
    cols_without_lib = [x for x in grouping_cols if x != 'LIB']
    cols_without_filesize = [x for x in grouping_cols if x != 'FILE_BYTES']

    # Get the mean from all the executions of the benchmark based on the grouping cols
    df = df.groupby(grouping_cols).mean().reset_index()

    # Calculate paces and performance coefficient
    df["ENCRYPT_PACE"] = df.apply(lambda row: row["ENCRYPT_T"]/row["FILE_BYTES"], axis=1)
    df["DECRYPT_PACE"] = df.apply(lambda row: row["DECRYPT_T"]/row["FILE_BYTES"], axis=1)
    df["PERFORMANCE_COEFFICIENT"] = df.apply(lambda row: row["ENCRYPT_PACE"]+row["DECRYPT_PACE"], axis=1)

    # Remove LIB from the grouping columns for selecting library with highest performance coefficient (lowest pace rate)
    df = df.loc[df.groupby(cols_without_lib)["PERFORMANCE_COEFFICIENT"].idxmin()]

    # Get the lower bound intervals
    df = df.loc[df.groupby(cols_without_filesize)["FILE_BYTES"].idxmin()]

    # Save sorted for easier viz
    df.sort_values(by=cols_without_lib).to_csv("grouped_intervals.csv", columns=grouping_cols)


add_sec_level()
get_winners(benchmark_df, ['LIB', 'ALG', 'KEY_LEN', 'BLOCK_MODE', 'FILE_BYTES', 'SECURITY_LEVEL'])

print("Done!")
