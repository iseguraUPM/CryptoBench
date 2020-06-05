import pandas as pd

mydf = pd.read_csv('dummy_data.csv')


def fill_security_levels(df):
    sec_levels = df['SEC_LEVEL'].unique()
    max_size = df['FILE_BYTES'].max()

    for sec_level in sec_levels:
        file_bytes = 1
        while file_bytes < max_size + 1:
            if df[(df['SEC_LEVEL'] == sec_level) & (df['FILE_BYTES'] == file_bytes)].shape[0] == 0:
                df = df.append(((df[(df['SEC_LEVEL'] == sec_level) & (df['FILE_BYTES'] == file_bytes/2)]).replace({'FILE_BYTES': file_bytes/2}, file_bytes)), ignore_index=True)
            file_bytes = file_bytes * 2


fill_security_levels(mydf)

mydf.to_csv('dummy_filled.csv', index=False)