import pandas as pd
import numpy as np

from pre_generator import add_sec_level

df = pd.read_csv('benchmark_x86_64.csv')
modes_df = pd.read_csv('block_cipher_modes_w.csv')
rounds_df = pd.read_csv('block_cipher_rounds.csv')

# Add security level
df = add_sec_level(df, modes_df, rounds_df, 5)

# Select file sizes to reduce search space
df['LOG'] = np.log(df['FILE_BYTES']) / np.log(2)
df = df[df['LOG'] == df['LOG'].astype(int)]

# Compute pace
df['PACE'] = df['ENCRYPT_T'] / df['FILE_BYTES']

# Average pace repetitions
cols = ['LIB', 'ALG', 'KEY_LEN', 'BLOCK_MODE', 'SEC_LEVEL', 'FILE_BYTES']
df = df.groupby(cols, as_index=False).mean()

# Percentile of pace per file size. Higher is better
df['RANK'] = df.sort_values(by='PACE').groupby(['SEC_LEVEL', 'FILE_BYTES'])['PACE'].rank(method='min', ascending=False, pct=True)

# Filter 10% best in pace per file size
df = df[df['RANK'] >= 0.75].reset_index()

# Recover new list of ciphers
cols = ['LIB', 'ALG', 'KEY_LEN', 'BLOCK_MODE', 'SEC_LEVEL']
ciphers = df.groupby(cols).size().reset_index()

int_scale = 1000000

with open('query.txt', 'w') as f:
    # Print list of file sizes in order
    blocks = df['FILE_BYTES'].sort_values(ascending=False).unique()
    f.write(" ".join(list(map(str, blocks))))
    f.write("\n")
    
    # Print int scale for pace data
    f.write(str(int_scale) + "\n")

    # Print pace per block size in cipher order
    pace_per_block = []
    for index, row in ciphers.iterrows():
        line = []
        line.append(row['LIB'] + "-" + row['ALG'] + "-" + str(row['KEY_LEN']) + "-" + row['BLOCK_MODE'])
        line.append(row['SEC_LEVEL'])
        for size in blocks:
            pace = df[(df['LIB'] == row['LIB']) & (df['ALG'] == row['ALG']) & (df['KEY_LEN'] == row['KEY_LEN']) & (df['BLOCK_MODE'] == row['BLOCK_MODE']) & (df['FILE_BYTES'] == size)]['PACE']
            if len(pace) == 0:
                line.append(0)
            else:
                line.append(int(pace.iloc[0] * int_scale))
        pace_per_block.append(line)

    for paces in pace_per_block:
        f.write(" ".join(map(str, paces)))
        f.write("\n")
