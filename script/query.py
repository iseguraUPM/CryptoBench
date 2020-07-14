import sys
import math
import pandas as pd
import numpy as np
from queue import Queue

from pre_generator import add_sec_level

df = pd.read_csv('benchmark_x86_64.csv')
modes_df = pd.read_csv('block_cipher_modes_w.csv')
rounds_df = pd.read_csv('block_cipher_rounds.csv')

# Add security level
df = add_sec_level(df, modes_df, rounds_df, 5)

# Select file sizes to reduce search space
df['LOG'] = np.log(df['FILE_BYTES']) / np.log(4)
df = df[df['LOG'] == df['LOG'].astype(int)]

# Compute pace
df['PACE'] = df['ENCRYPT_T'] / df['FILE_BYTES']
df['PACE'] = df['PACE'] + df['DECRYPT_T'] / df['FILE_BYTES']

# Average pace repetitions
cols = ['LIB', 'ALG', 'KEY_LEN', 'BLOCK_MODE', 'SEC_LEVEL', 'FILE_BYTES']
df = df.groupby(cols, as_index=False).mean()

# Percentile of pace per file size. Higher is better
df['RANK'] = df.sort_values(by='PACE').groupby(['SEC_LEVEL', 'FILE_BYTES'])['PACE'].rank(method='min', ascending=False, pct=True)

# Filter 10% best in pace per file size
df = df[df['RANK'] >= 0.90].reset_index()

# Recover new list of ciphers
cols = ['LIB', 'ALG', 'KEY_LEN', 'BLOCK_MODE', 'SEC_LEVEL']
ciphers = df.groupby(cols).size().reset_index()

with open('query.txt', 'w') as f:
    # Print list of file sizes in order
    f.write('Blocks: \n')
    blocks = df['FILE_BYTES'].sort_values(ascending=False).unique()
    f.write('{%s }\n' % ', '.join(map(str, blocks)))
    f.write("Length: %s\n\n" % str(len(blocks)))

    # Print cipher names
    f.write('Ciphers: \n')
    names = ciphers.apply(lambda row: '\"' + row['LIB'] + '-' + row['ALG'] + '-' + str(row['KEY_LEN']) + '-' + row['BLOCK_MODE'] + '\"', axis=1)
    f.write('{%s }\n' % ', '.join(names))
    f.write("Length: %s\n\n" % str(len(ciphers)))

    # Print security level in cipher order
    f.write('Sec: \n')
    sec_levels = ciphers['SEC_LEVEL']
    f.write('{%s }\n' % ', '.join(map(str, sec_levels)))
    f.write("Length: %s\n\n" % str(len(ciphers)))

    # Print pace per block size in cipher order
    pace_per_block = []
    for index, row in ciphers.iterrows():
        paces = []
        for size in blocks:
            pace = df[(df['LIB'] == row['LIB']) & (df['ALG'] == row['ALG']) & (df['KEY_LEN'] == row['KEY_LEN']) & (df['BLOCK_MODE'] == row['BLOCK_MODE']) & (df['FILE_BYTES'] == size)]['PACE']
            if len(pace) == 0:
                paces.append(0)
            else:
                paces.append(int(pace.iloc[0] * 1000000.0))
        pace_per_block.append(paces)

    f.write('Paces: \n{\n')
    for paces in pace_per_block[:-1]:
        f.write('{%s }, \n' % ', '.join(map(str, paces)))
    f.write('{%s }\n' % ', '.join(map(str, pace_per_block[-1])))
    f.write('}\n')