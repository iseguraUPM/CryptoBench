import pandas as pd

df = pd.read_csv('dummy_data.csv')

sec_levels = df['SEC_LEVEL'].unique()

min_size = df['FILE_BYTES'].min()
max_size = df['FILE_BYTES'].max()

for sec_level in sec_levels:
    file_bytes = 1
    print('sec_level-', sec_level)
    while file_bytes < max_size + 1:
        print('file_bytes-', file_bytes)
        if df[(df['SEC_LEVEL'] == sec_level) & (df['FILE_BYTES'] == file_bytes)].shape[0] == 0:
            df = df.append(((df[(df['SEC_LEVEL'] == sec_level) & (df['FILE_BYTES'] == file_bytes/2)]).replace({'FILE_BYTES': file_bytes/2}, file_bytes)), ignore_index=True)
        file_bytes = file_bytes * 2

df.to_csv('dummy_filled.csv', index=False)