import pandas as pd
import math

def add_sec_level(df, rounds_df, modes_df, sec_coefficient_range):

    

    rounds_df['tmp'] = 1
    modes_df['tmp'] = 1
    block_modes_df = pd.merge(rounds_df, modes_df, on=['tmp'])
    block_modes_df = block_modes_df.drop('tmp', axis=1)

    df = pd.merge(df, block_modes_df, on=['ALG', 'KEY_LEN', 'BLOCK_LEN', 'BLOCK_MODE'], how='left')

    # Calculate the security coefficient
    df['SECURITY_COEFFICIENT'] = df.apply(lambda row: (math.log2(row['KEY_LEN']) + math.log2(row['BLOCK_LEN'])) * math.log(row['ROUNDS']) * row['SEC_WEIGHT'], axis=1)
    df = df[df['SECURITY_COEFFICIENT'] != 0]

    min_sec_coeff = df['SECURITY_COEFFICIENT'].min()
    max_sec_coeff = df['SECURITY_COEFFICIENT'].max()

    # Normalize the security coefficient
    df['SECURITY_NORM'] = df.apply(lambda row: (row['SECURITY_COEFFICIENT'] - min_sec_coeff) / (max_sec_coeff-min_sec_coeff), axis=1)

    # Copy to another dataframe to get unique order and normalize by that order. We then merge it back.
    sec_levels = pd.DataFrame(data=df['SECURITY_NORM'].drop_duplicates().sort_values().reset_index())
    sec_levels['SEC_LEVEL'] = sec_levels.apply(lambda row: int(1+round(row.name * (sec_coefficient_range-1)/sec_levels.shape[0])), axis=1)
    sec_levels = sec_levels[['SEC_LEVEL', 'SECURITY_NORM']]
    df = pd.merge(df, sec_levels, on=['SECURITY_NORM'], how='left')

    df = df[['LIB', 'ALG', 'KEY_LEN', 'BLOCK_MODE', 'FILE_BYTES', 'ENCRYPT_T', 'DECRYPT_T', 'SEC_LEVEL']]

    base_df = df.copy()
    for level in df['SEC_LEVEL'].unique():
        other_levels = base_df.copy()
        other_levels.loc[other_levels['SEC_LEVEL'] > level, 'SEC_LEVEL'] = level
        df = df.append(other_levels)

    return df


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
    df = df.loc[df.groupby(["FILE_BYTES", "SEC_LEVEL"])["PERFORMANCE_COEFFICIENT"].idxmin()]

    # Get the lower bound intervals
    #df = df.loc[df.groupby(cols_without_filesize)["FILE_BYTES"].idxmin()]

    # Save sorted for easier viz
    #df.sort_values(by=cols_without_lib).to_csv("grouped_intervals.csv", columns=grouping_cols)
    df = df.sort_values(by=cols_without_lib)[grouping_cols]

    return df

def fill_security_levels(df):
    sec_levels = df['SEC_LEVEL'].unique()
    max_size = df['FILE_BYTES'].max()

    for sec_level in sec_levels:
        file_bytes = 1
        while file_bytes < max_size + 1:
            if df[(df['SEC_LEVEL'] == sec_level) & (df['FILE_BYTES'] == file_bytes)].shape[0] == 0:
                df = df.append(((df[(df['SEC_LEVEL'] == sec_level) & (df['FILE_BYTES'] == file_bytes/2)]).replace({'FILE_BYTES': file_bytes/2}, file_bytes)), ignore_index=True)
            file_bytes = file_bytes * 2
    return df

def generate_dataset(benchmark_df, rounds_df, modes_df, max_security_level):
    benchmark_df = add_sec_level(benchmark_df, rounds_df, modes_df, max_security_level)
    benchmark_df = get_winners(benchmark_df, ['LIB', 'ALG', 'KEY_LEN', 'BLOCK_MODE', 'FILE_BYTES', 'SEC_LEVEL'])
    benchmark_df = fill_security_levels(benchmark_df)
    return benchmark_df