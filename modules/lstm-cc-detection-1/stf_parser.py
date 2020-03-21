import sys
import pandas as pd


def load_csv_data(dataset_file):
    with open(dataset_file, 'rb') as csvfile:
        rawreader = pd.read_csv(csvfile, delimiter='|', names=[
                                "note", "label", "model_id", "state"], skipinitialspace=True)
        pd.core.strings.str_strip(rawreader['note'])
        pd.core.strings.str_strip(rawreader['label'])
        pd.core.strings.str_strip(rawreader['model_id'])
        pd.core.strings.str_strip(rawreader['state'])

    if len(rawreader) is 0:
        return

    return rawreader

if __name__ == "__main__":
    if(len(sys.argv) < 2):
        print('need to specify csv dataset filename as argument.')
    filename = sys.argv[1]
    df = load_csv_data(filename)
    if df is None:
        sys.exit(1)
    normal_data = filter_by_string(df, 'label', 'Normal')['state'].values.tolist()
    botnet_data = filter_by_string(df, 'label', 'Botnet')['state'].values.tolist()
