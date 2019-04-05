import sys
from datetime import datetime
from datetime import timedelta
import os
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import pandas as pd

categories = {}

def make_categorical(dataset, cat):
    global categories
    '''
    Convert one column to a categorical type
    '''
    # Converts the column to cotegorical
    dataset[cat] = pd.Categorical(dataset[cat])
    categories[cat] = dataset[cat].cat
    # Convert the categories to int. Use this with caution!! we don't want an algorithm
    # to learn that an Orange=1 is less than a pearl=2
    #dataset[cat] = categories[cat].cat.codes
    dataset[cat] = dataset[cat].cat.codes
    return dataset

def process_features2(dataset):
    '''
    Discards some features of the dataset and can create new.
    '''
    try:
      dataset = dataset.drop('StartTime', axis=1)
    except ValueError:
      pass
    dataset.reset_index()
    try:
      dataset = dataset.drop('SrcAddr', axis=1)
    except ValueError:
      pass
    try:
      dataset = dataset.drop('DstAddr', axis=1)
    except ValueError:
      pass
    try:
      dataset = dataset.drop('sTos', axis=1)
    except ValueError:
      pass
    try:
      dataset = dataset.drop('dTos', axis=1)
    except ValueError:
      pass
    # Create categorical features
    try:
      dataset.Dir = categories['Dir'].codes
    except ValueError:
      pass
    try:
      dataset.Proto = categories['Proto'].codes
    except ValueError:
      pass
    try:
      # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
      dataset.Sport = categories['Sport'].codes
    except ValueError:
      pass
    try:
      dataset.State = categories['State'].codes
    except ValueError:
      pass
    try:
      # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
      dataset.Dport = categories['Dport'].codes
    except ValueError:
      pass
    try:
      # Convert Dur to float
      dataset.Dur = dataset.Dur.astype('float')
    except ValueError:
      pass
    try:
      # Convert TotPkts to float
      dataset.Dur = dataset.TotPkts.astype('float')
    except ValueError:
      pass
    try:
      # Convert SrcPkts to float
      dataset.Dur = dataset.SrcPkts.astype('float')
    except ValueError:
      pass
    try:
      # Convert TotBytes to float
      dataset.Dur = dataset.TotBytes.astype('float')
    except ValueError:
      pass
    try:
      # Convert SrcBytes to float
      dataset.Dur = dataset.SrcBytes.astype('float')
    except ValueError:
      pass
    return dataset

def process_features1(dataset):
    '''
    Discards some features of the dataset and can create new.
    '''
    try:
      dataset = dataset.drop('StartTime', axis=1)
    except ValueError:
      pass
    dataset.reset_index()
    try:
      dataset = dataset.drop('SrcAddr', axis=1)
    except ValueError:
      pass
    try:
      dataset = dataset.drop('DstAddr', axis=1)
    except ValueError:
      pass
    try:
      dataset = dataset.drop('sTos', axis=1)
    except ValueError:
      pass
    try:
      dataset = dataset.drop('dTos', axis=1)
    except ValueError:
      pass
    # Create categorical features
    try:
      dataset = make_categorical(dataset, 'Dir')
    except ValueError:
      pass
    try:
      dataset = make_categorical(dataset, 'Proto')
    except ValueError:
      pass
    try:
      # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
      dataset = make_categorical(dataset, 'Sport')
    except ValueError:
      pass
    try:
      dataset = make_categorical(dataset, 'State')
    except ValueError:
      pass
    try:
      # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
      dataset = make_categorical(dataset, 'Dport')
    except ValueError:
      pass
    try:
      # Convert Dur to float
      dataset.Dur = dataset.Dur.astype('float')
    except ValueError:
      pass
    try:
      # Convert TotPkts to float
      dataset.Dur = dataset.TotPkts.astype('float')
    except ValueError:
      pass
    try:
      # Convert SrcPkts to float
      dataset.Dur = dataset.SrcPkts.astype('float')
    except ValueError:
      pass
    try:
      # Convert TotBytes to float
      dataset.Dur = dataset.TotBytes.astype('float')
    except ValueError:
      pass
    try:
      # Convert SrcBytes to float
      dataset.Dur = dataset.SrcBytes.astype('float')
    except ValueError:
      pass
    return dataset

def process_flow(filename):
    """
    """
    global categories
    dateparse = lambda x: pd.datetime.strptime(x, '%Y/%m/%d %H:%M:%S.%f') # 2018/07/22 13:01:34.892833

    tfile = open(filename, 'r')
    dataset = pd.read_table(tfile, sep='\t', parse_dates=['StartTime'] , date_parser=dateparse)
    tfile.close()

    dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
    dataset.Label = dataset.Label.str.replace(r'(^.*Malware.*$)', 'Malware')

    #print(dataset.describe(include='all'))

    # Process features
    dataset = process_features1(dataset)
    #print(dataset.describe(include='all'))

    # Separate
    y_dataset = dataset['Label']
    X_dataset = dataset.drop('Label', axis=1)

    sc = StandardScaler()
    sc.fit(X_dataset)
    X_dataset_std = sc.transform(X_dataset)
    #print(X_dataset_std)


    clf = RandomForestClassifier(n_estimators=3, criterion='entropy', random_state=1234)
    clf.fit(X_dataset_std, y_dataset)
    score = clf.score(X_dataset_std, y_dataset)
    print(score)

    f = open('scale-new.bin', 'wb')
    data = pickle.dumps(sc)
    f.write(data)
    f.close()

    f = open('model-new.bin', 'wb')
    data = pickle.dumps(clf)
    f.write(data)
    f.close()
    print(categories)

    f = open('categories.bin', 'wb')
    data = pickle.dumps(categories)
    f.write(data)
    f.close()


    """
    # Predict
    #other = process_features2(dataset)
    #other = other.drop('Label',axis=1)
    other = dataset.drop('Label',axis=1)
    l = len(dataset)
    #for i in range(0,l+1):
    for i in range(0,1):

        data = other.iloc[i:i+1]
        fstd = sc.transform(data)
        print('Flow: {}. Std: {}'.format(data, fstd))
        #pred = clf.predict(fstd)
        #print('Flow: {}. Label: {}'.format(data, pred))
        print(dataset.iloc[i:i+1])
        print(data)
        print(fstd)
    """

    f = open('scale-new.bin', 'rb')
    sc = pickle.load(f)
    f.close()
    f = open('model-new.bin', 'rb')
    clf = pickle.load(f)
    f.close()
    f = open('categories.bin', 'rb')
    categories = pickle.load(f)
    f.close()

    newfile = open(filename, 'r')

    flow = newfile.readline()
    flow = newfile.readline()
    while flow:
        sflow = flow.split('	')

        # convert the flow to a pandas dataframe
        dflow = pd.DataFrame([sflow], columns=['StartTime','Dur','Proto','SrcAddr','Sport','Dir','DstAddr','Dport','State','sTos','dTos','TotPkts','TotBytes','SrcBytes','SrcPkts','Label'])
        # Process features
        dflow = process_features2(dflow)
        label = str(dflow.Label)
        label = label.split()[1].replace('\\n','').replace('flow=','')

        dflow = dflow.drop('Label', axis=1)

        #flow_std = newscaler.transform(dflow)
        flow_std = sc.transform(dflow)

        pred = clf.predict(flow_std)
        print('\tLabel: {}. Prediction: {}'.format(label, pred[0]))
        #print('\tFlow: {}. Prediction: {}'.format(dflow, pred[0]))
        """
        print(flow)
        print(sflow)
        print(dflow)
        print(flow_std)
        break
        """

        flow = newfile.readline()

if __name__ == '__main__':  
    process_flow('./concatenated.binetflow')



