import sys
import pandas as pd
from queue import Queue

from pre_generator import add_sec_level

df = pd.read_csv('benchmark_x86_64.csv')
modes_df = pd.read_csv('block_cipher_modes_w.csv')
rounds_df = pd.read_csv('block_cipher_rounds.csv')

df = add_sec_level(df, modes_df, rounds_df, 5)

print('Blocks: ')
blocks = df['FILE_BYTES'].sort_values().unique()
print('{' + ','.join(map(str, blocks)) + '}')
print("Length: " + str(len(blocks)))

df['PACE'] = df['ENCRYPT_T'] / df['FILE_BYTES']
df['PACE'] = df['PACE'] + df['DECRYPT_T'] / df['FILE_BYTES']

cols = ['LIB', 'ALG', 'KEY_LEN', 'BLOCK_MODE', 'SEC_LEVEL']
ciphers = df.groupby(cols).size().reset_index()


print('Sec: ')
sec_levels = ciphers['SEC_LEVEL']
print('{' + ','.join(map(str, sec_levels)) + '}')

def getPace(row, size):
    lib = row['LIB']
    alg = row['ALG']
    key = row['KEY_LEN']
    blockm = row['BLOCK_MODE']
    repetitions = df[(df['LIB'] == lib) & (df['ALG'] == alg) & (df['KEY_LEN'] == key) & (df['BLOCK_MODE'] == blockm) & (df['FILE_BYTES'] == size)]
    if (repetitions.shape[0] == 0):
        return '0'
    pace = repetitions['PACE'].mean()
    return str(int(pace * 1000000.0))


pace_str = ''
for index, row in ciphers.iterrows():
    paces = []
    for size in blocks:
        paces.append(getPace(row, size))
    pace_str += '{' + ','.join(paces) + '},\n'

print(pace_str)