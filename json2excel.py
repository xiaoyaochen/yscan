""" python3 -m pip install pandas==1.3.4 """
import pandas as pd 
import argparse
import os
import json

def flatten_json(nested_json: dict, exclude: list=[''], sep: str='_') -> dict:
    """
    Flatten a list of nested dicts.
    """
    out = dict()
    def flatten(x , name: str='', exclude=exclude):
        if type(x) is dict:
            for a in x:
                if a not in exclude:
                    flatten(x[a], f'{name}{a}{sep}')
        elif type(x) is list:
            i = 0
            for a in x:
                flatten(a, f'{name}{i}{sep}')
                i += 1
        else:
            out[name[:-1]] = x

    flatten(nested_json)
    return out

def merge_columns(cols):
    return ','.join([str(match) for match in [col for col in cols] if str(match) != 'nan'])


def dealer_yscan_out(file):
    with open( file, 'r') as inputFile:
        json_data = json.loads(inputFile.read() )  # load json content
    if not json_data:
        raise Exception("errorrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr")
    df = pd.DataFrame([flatten_json(x) for x in json_data])

    df['finger'] = df.filter(regex = r'^apps_\d_slug$').apply(merge_columns, axis=1)

    columns = [i for i in df.columns if i in ['ip' , 'host' , 'port' ,
                'finger_print_service' ,
                'url','sslcert_Subject_CommonName' ,
                'title','status_code' , 'finger'
        ]]

    df = df[columns].drop_duplicates(subset=['ip' , 'host' , 'port'],keep='first')

    return df


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Converting json files into csv for Tableau processing')
    parser.add_argument(
        "-i", "--input", dest="input", help="input yscan output json ", required=True)
    parser.add_argument(
        "-o", "--output", dest="output", help="output excel ", required=True)
    
    args = parser.parse_args()
    yscan_df = dealer_yscan_out(args.input)
    with pd.ExcelWriter(
        f'{os.getcwd()}/{args.output}'
    ) as writer:
        yscan_df.to_excel(writer, sheet_name='portscan',index=False)