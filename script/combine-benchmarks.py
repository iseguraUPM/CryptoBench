import pandas as pd
import numpy as np
import sys

df_enc = pd.read_csv('benchmark_enc.csv')
df_dec = pd.read_csv('benchmark_dec.csv')

# Check that the lengths are equal
if df_enc.shape[0] != df_dec.shape[0]:
    print('Encrypt and decrypt csv files have different lengths.')
    sys.exit()

# Add new columns to the dataframe
df_enc['DECRYPT_T'] = np.nan
df_enc['DECRYPT_IO_T'] = np.nan


# Iterate through the encrypt df
for index, row in df_enc.iterrows():
    dec_attrs = df_dec.iloc[[index]]
    df_enc.loc[index, 'DECRYPT_T'] = dec_attrs['DECRYPT_T'].values[0]
    df_enc.loc[index, 'DECRYPT_IO_T'] = dec_attrs['DECRYPT_IO_T'].values[0]

    if not (row['DEVICE'] == dec_attrs['DEVICE'].values[0]
            and row['ARCH'] == dec_attrs['ARCH'].values[0]
            and row['LIB'] == dec_attrs['LIB'].values[0]
            and row['ALG'] == dec_attrs['ALG'].values[0]
            and row['KEY_LEN'] == dec_attrs['KEY_LEN'].values[0]
            and row['BLOCK_MODE'] == dec_attrs['BLOCK_MODE'].values[0]
            and row['BLOCK_LEN'] == dec_attrs['BLOCK_LEN'].values[0]
            and row['FILE_BYTES'] == dec_attrs['FILE_BYTES'].values[0]
            and row['CIPHERTEXT_BYTES'] == dec_attrs['CIPHERTEXT_BYTES'].values[0]):
        print('No match between encrypt and decrypt data.')
        print('ENCRYPT: ', row['DEVICE'], "_", row['ARCH'], "_", row['LIB'], "_", row['ALG'], "_", row['KEY_LEN'], "_", row['BLOCK_MODE'], "_", row['BLOCK_LEN'], "_", row['FILE_BYTES'], "_", row['CIPHERTEXT_BYTES'], sep='')
        print('DECRYPT: ', dec_attrs['DEVICE'].values[0], "_", dec_attrs['ARCH'].values[0], "_", dec_attrs['LIB'].values[0], "_", dec_attrs['ALG'].values[0], "_", dec_attrs['KEY_LEN'].values[0], "_", dec_attrs['BLOCK_MODE'].values[0], "_", dec_attrs['BLOCK_LEN'].values[0], "_", dec_attrs['FILE_BYTES'].values[0], "_", dec_attrs['CIPHERTEXT_BYTES'].values[0], sep='')

df_enc = df_enc.astype({"DECRYPT_T": int, "DECRYPT_IO_T": int})
df_enc.to_csv('benchmark_combined.csv', index=False)