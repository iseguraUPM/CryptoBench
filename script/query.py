import sys
import pandas as pd
from queue import Queue

from pre_generator import generate_dataset


df = pd.read_csv('benchmark_x86_64.csv')

blocks = df["FILE_BYTES"].unique()
print(','.join(map(str, blocks)))
print(len(blocks))

df['PACE'] = df["ENCRYPT_T"] / df["FILE_BYTES"]
df["PACE"] = df["PACE"] + df["DECRYPT_T"] / df["FILE_BYTES"]

cols = ['LIB', 'ALG', 'KEY_LEN', 'BLOCK_MODE']
ciphers = df.groupby(cols).size().reset_index()
print(ciphers.iloc[316])

max_pace = df['PACE'].max()

def getPace(row, size):
    lib = row['LIB']
    alg = row['ALG']
    key = row['KEY_LEN']
    blockm = row['BLOCK_MODE']
    repetitions = df[(df['LIB'] == lib) & (df['ALG'] == alg) & (df['KEY_LEN'] == key) & (df['BLOCK_MODE'] == blockm) & (df['FILE_BYTES'] == size)]
    if (repetitions.shape[0] == 0):
        return str(int(max_pace * 10.0) + 1)
    pace = repetitions['PACE'].mean()
    return str(int(pace * 1000000.0))

'''pace_str = ''
for index, row in ciphers.iterrows():
    paces = []
    for size in blocks:
        paces.append(getPace(row, size))
    pace_str += '{' + ','.join(paces) + '},\n'
'''
print(pace_str)