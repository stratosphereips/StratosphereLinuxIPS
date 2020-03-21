from __future__ import division, print_function

import sys
import pandas as pd
from sklearn import metrics
from sklearn.cross_validation import train_test_split
from random import shuffle

import lstm_dataset_functions
from keras.models import Sequential
from keras.layers.core import Dense, Activation, Masking, Dropout
from keras.layers.recurrent import GRU
from keras.callbacks import ModelCheckpoint


def filter_by_string(df, col, string):
    '''
    Filters a dataframe column by a string.
    '''
    return df[df[col].str.contains(string, regex=False) == True]


def load_csv_data(dataset_file):
    with open(dataset_file, 'rb') as csvfile:
        rawreader = pd.read_csv(csvfile, delimiter='|', names=[ "note", "label", "model_id", "state"], skipinitialspace=True)
        # pd.core.strings.str_strip(rawreader['note'])
        # pd.core.strings.str_strip(rawreader['label'])
        # pd.core.strings.str_strip(rawreader['model_id'])
        # pd.core.strings.str_strip(rawreader['state'])

    if len(rawreader) is 0:
        return

    return rawreader


def split_data(data, split_pct=0.1):
        '''
        Splits data into training and testing.
        '''
        shuffle(data)
        return train_test_split(data, test_size=split_pct)


def build_lstm(input_shape):
    model = Sequential()
    model.add(Masking(input_shape=input_shape, mask_value=-1.))
    model.add(GRU(128, return_sequences=False))

    # model.add(GRU(128, return_sequences=False))
    # Add dropout if overfitting
    # model.add(Dropout(0.5))
    model.add(Dense(1))
    model.add(Activation('sigmoid'))
    model.compile(loss='binary_crossentropy', optimizer='rmsprop', metrics=['accuracy'])
    return model


def train_model(model, x_train, y_train, batch_size, checkpointer, epochs=20):
    print("Training model...")

    # FIT THE MODEL
    model.fit(x_train, y_train, nb_epoch=epochs, batch_size=batch_size,
              validation_split=0.3,
              verbose=1, callbacks=[checkpointer], shuffle=True)


def test_model(model, x_test, y_test):
    test_preds = model.predict_classes(x_test, len(x_test), verbose=1)
    print ("Testing Dataset) ", metrics.confusion_matrix(y_test, test_preds))


if __name__ == "__main__":
    if(len(sys.argv) < 2):
        print('need to specify csv raw dataset filename as argument.')
        sys.exit(1)
    # csv file with the data
    filename = sys.argv[1]
    # Load the dataset into a pandas dataframe
    df = load_csv_data(filename)

    if df is None:
        sys.exit(1)

    # FILTER by Protocol and then Category
    normal_data = filter_by_string(filter_by_string(df, 'label', 'UDP'), 'label', 'Normal')['state'].values.tolist()
    botnet_data = filter_by_string(filter_by_string(df, 'label', 'UDP'), 'label', 'Botnet')['state'].values.tolist()

    # Set 0 or 1 depending on the sample Category
    y_data = [0 for i in xrange(len(normal_data))] + [1 for i in xrange(len(botnet_data))]

    # Make sure this is right
    assert len(normal_data) > 0 and len(botnet_data) > 0
    assert len(normal_data) + len(botnet_data) == len(y_data)

    data = zip(normal_data + botnet_data, y_data)

    # split into training and testing
    train_data, test_data = split_data(data, split_pct=0.2)
    train_x_data, train_y_data = zip(*train_data)

    # set the max number of steps (max length of sequences)
    maxlen = min(len(max(train_x_data, key=len)), 100)

    # vectorize the data to feed the net
    train_x_data, train_y_data = stf_dataset.vectorize(train_x_data, train_y_data, mode='int', sampling='OverSampler', maxlen=maxlen, minlen=maxlen, start_offset=5)

    # build the net
    model = build_lstm(input_shape=(maxlen, 4))
    filename = '/tmp/weights_latest.hdf5'
    # a checkpointer to save the best trained model
    checkpointer = ModelCheckpoint(filepath=filename,
                                verbose=0, save_best_only=True)

    # train the model
    train_model(model, train_x_data, train_y_data,
            checkpointer=checkpointer, batch_size=len(train_x_data) / 10, epochs=40)
    test_x_data, test_y_data = zip(*test_data)
    model.load_weights(filename)

    # test the model
    test_model(model, *stf_dataset.vectorize(test_x_data, test_y_data, mode='int',
        maxlen=maxlen, minlen=0))
