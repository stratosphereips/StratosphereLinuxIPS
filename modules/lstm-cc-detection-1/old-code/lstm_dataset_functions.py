# -*- coding: utf-8 -*-
"""
Created on Tue Sep 15 16:11:42 2015

@author: h2o

Loads datasets, one line per example, shuffles the data and returns 2 tuples
with train and test splits
"""

from __future__ import absolute_import
from __future__ import print_function

import numpy as np
from collections import OrderedDict
# import pandas as pd
from keras.preprocessing import sequence
from keras.preprocessing import text
from unbalanced_dataset import OverSampler, UnderSampler, OneSidedSelection
from unbalanced_dataset import TomekLinks, SMOTETomek, SMOTE
from unbalanced_dataset import CondensedNearestNeighbour, NearMiss, NeighbourhoodCleaningRule
import sys


def text_filter():
    f = '\t\n'
    return f



def load_data(test_split=0.2, maxlen=100, seed=None):
    X, Y = shuffle_data(load_dataset(maxlen=maxlen))
    return split_data(X, Y, test_split)


def tokenize(word_model, X):
    tokenizer = text.Tokenizer(
        nb_words=word_model, filters=text_filter(), lower=False, split=" ")
    tokenizer.fit_on_texts(X)
    x_sequences = np.asarray(tokenizer.texts_to_sequences(X))
    print (tokenizer.word_counts)
    return x_sequences


def one_hot(word_model, n):
    return text.one_hot(
        word_model, n, filters=text_filter(), lower=False, split=" ")


def vectorize(X, Y, word_model=None, maxlen=100, mode='state',
            sampling='None', shuffle=True, minlen=0, start_offset=0):
    '''
    Vectorize the samples X into a 3D Tensor (samples_count, timesteps, input_dim)
    where timesteps is the max length of the samples, starting from the minlen
    character of each model
    '''
    if word_model is None:
        word_model = '.,+*0abcdefghiABCDEFGHIrstuvwxyzRSTUVWXYZ123456789'

    time_chars = '.,+*0'
    word_states = 'abcdefghiABCDEFGHIrstuvwxyzRSTUVWXYZ123456789'

    X = X[start_offset:]

    # word_model_set = sorted(set(word_model))
    word_model_set = [c for c in word_model]

    Y_data = []
    if mode == 'int':

        '''
        size_states -> iterate every 3 columns. ex: columns 1-2-3 for small size
        duration_states -> example: columns 1-4-7 for short duration
        periodicity_states -> iterate every row. ex: row 1 for strong periodicity
        time_states -> first 5 states
        '''
        n_states = 4
        time_states = []


        states = []

        for a in range(len(time_chars)):
            states.append([0, 0, 0, a+1])

        for a in range(5):
            for b in range(3):
                for c in range(3):
                    states.append([c+1, b+1, a+1, 0])

        dict_states = {c: states[i] for i, c in enumerate(word_model_set)}

        j = []
        for i, sentence in enumerate(X):
            if len(sentence) >= minlen:
                j.append([char for char in list(sentence)])
                Y_data.append(Y[i])

        X_array = np.asarray(j)
        Y_data = np.asarray(Y_data)

        X_data = np.full(
            (len(X_array), maxlen, n_states), -1, dtype=np.float)
        for i, sentence in enumerate(X_array):
            for t, char_state in enumerate(sentence[:maxlen]):
                # n_sample, timestep, value
                for n, a in enumerate(dict_states.get(char_state)):
                    X_data[i, t, n] = a

        if sampling != 'None':
            X_data, Y_data = apply_sampling(
                X_data, Y_data, sampling, n_states, maxlen)
            X_data = np.reshape(
                X_data, (len(X_data), maxlen, n_states))

        if shuffle is True:
            return shuffle_data(X_data, Y_data)
        else:
            return X_data, Y_data

    elif mode == 'bool':
        n_states = len(word_model_set)
        # Build dictionary
        word_model_idx = dict((c, i) for i, c in enumerate(word_model_set))
        # print (sorted(word_model_idx))
        j = []
        for i, sentence in enumerate(X):
            if len(sentence) >= minlen:
                j.append([word_model_idx[char] for char in list(sentence)])
                Y_data.append(Y[i])

        X_array = np.asarray(j)
        Y_data = np.asarray(Y_data)

        X_data = np.zeros(
            (len(X_array), maxlen, n_states), dtype=np.int8)
        for i, sentence in enumerate(X_array):
            for t, char_idx in enumerate(sentence[:maxlen]):
                # with masking
                X_data[i, maxlen - t - 1, char_idx] = 1
                # without masking
                # X_data[i, t, char_idx] = 1

        if sampling != 'None':
            X_data, Y_data = apply_sampling(
                X_data, Y_data, sampling, n_states, maxlen)
            X_data = np.reshape(
                X_data, (len(X_data), maxlen, n_states))

        if shuffle is True:
            return shuffle_data(X_data, Y_data)
        else:
            return X_data, Y_data

    elif mode == 'state':
        '''
        size_states -> iterate every 3 columns. ex: columns 1-2-3 for small size
        duration_states -> example: columns 1-4-7 for short duration
        periodicity_states -> iterate every row. ex: row 1 for strong periodicity
        time_states -> first 5 states

        For 16 states -> s s s d d d p p p p p t t t t t (bool)
        '''
        n_size_states = 3
        n_duration_states = 3
        n_periodicity_states = 5
        n_time_states = 5
        size_states = []
        duration_states = []
        time_states = []
        time_offset = n_size_states + n_duration_states + n_periodicity_states
        n_rows = n_periodicity_states
        n_cols = n_size_states * n_duration_states
        n_states = n_size_states + n_duration_states + \
            n_periodicity_states + n_time_states
        # Build dictionary
        word_model_idx = OrderedDict((c, i)
                                     for i, c in enumerate(word_model_set))
        time_states = [char for char in word_model_set if word_model_idx[
            char] < n_time_states]

        def is_time_state(state):
            return state in time_states

        char_states = [char for i, char in enumerate(
            word_model_set) if i >= n_time_states]
        char_states = np.reshape(
            np.asarray(char_states), (n_rows, n_cols))
        for i in range(0, n_size_states):
            size_states.append(
                [a + i * n_size_states for a in range(0, n_size_states)])
        for i in range(0, n_duration_states):
            duration_states.append(
                [a * n_duration_states + i for a in range(0, n_duration_states)])
        size_states = np.asarray(size_states)
        duration_states = np.asarray(duration_states)
        j = []
        for i, sentence in enumerate(X):
            if len(sentence) >= minlen:
                j.append([char for char in list(sentence)])
                Y_data.append(Y[i])

        X_array = np.asarray(j)
        Y_data = np.asarray(Y_data)

        X_data = np.zeros(
            (len(X_array), maxlen, n_states), dtype=np.int8)
        for i, sentence in enumerate(X_array):
            for t, char_state in enumerate(sentence[:maxlen]):
                if is_time_state(char_state):
                    offset = time_offset
                    X_data[i, maxlen - t - 1, offset +
                           time_states.index(char_state)] = 1
                else:
                    offset = 0
                    idx_x = np.where(char_states == char_state)
                    # set size bit
                    X_data[i, maxlen - t - 1, offset +
                           np.where(size_states == idx_x[1])[0]] = 1
                    # set duration bit
                    offset = n_size_states
                    X_data[i, maxlen - t - 1, offset +
                           np.where(duration_states == idx_x[1])[0]] = 1
                    # set periodicity bit
                    offset = offset + n_duration_states
                    X_data[i, maxlen - t - 1, offset + idx_x[0]] = 1
                # print('state: ', sentence[t])
                # print(X_data[i, maxlen - t - 1, :])
                # raw_input("Press Enter to continue...")

                # with masking
                # X_data[i, maxlen - t - 1, char_idx] = 1
                # without masking
                # X_data[i, t, char_idx] = 1

        if sampling != 'None':
            X_data, Y_data = apply_sampling(
                X_data, Y_data, sampling, n_states, maxlen)
            X_data = np.reshape(
                X_data, (len(X_data), maxlen, n_states))

        if shuffle is True:
            return shuffle_data(X_data, Y_data)
        else:
            return X_data, Y_data


def apply_sampling(X_data, Y_data, sampling, n_states, maxlen):
    ratio = float(np.count_nonzero(Y_data == 1)) / \
        float(np.count_nonzero(Y_data == 0))
    X_data = np.reshape(
        X_data, (len(X_data), n_states * maxlen))
    # 'Random over-sampling'
    if sampling == 'OverSampler':
        OS = OverSampler(ratio=ratio, verbose=True)
    # 'Random under-sampling'
    elif sampling == 'UnderSampler':
        OS = UnderSampler(verbose=True)
    # 'Tomek under-sampling'
    elif sampling == 'TomekLinks':
        OS = TomekLinks(verbose=True)
    # Oversampling
    elif sampling == 'SMOTE':
        OS = SMOTE(ratio=1, verbose=True, kind='regular')
    # Oversampling - Undersampling
    elif sampling == 'SMOTETomek':
        OS = SMOTETomek(ratio=ratio, verbose=True)
    # Undersampling
    elif sampling == 'OneSidedSelection':
        OS = OneSidedSelection(verbose=True)
    # Undersampling
    elif sampling == 'CondensedNearestNeighbour':
        OS = CondensedNearestNeighbour(verbose=True)
    # Undersampling
    elif sampling == 'NearMiss':
        OS = NearMiss(version=1, verbose=True)
    # Undersampling
    elif sampling == 'NeighbourhoodCleaningRule':
        OS = NeighbourhoodCleaningRule(verbose=True)
    # ERROR: WRONG SAMPLER, TERMINATE
    else:
        print('Wrong sampling variable you have set... Exiting...')
        sys.exit()
    # print('shape ' + str(X.shape))
    X_data, Y_data = OS.fit_transform(X_data, Y_data)
    return X_data, Y_data


def load_dataset(x_file='', y_file='', filter_chars=' \r\n', shuffle=True):
    X = [line.strip(filter_chars) for line in open(x_file)]
    Y = np.genfromtxt(y_file, dtype='int')
    if shuffle is True:
        X, Y = shuffle_data(X, Y)
    return X, Y


def shuffle_data(X, Y):
    rng_state = np.random.get_state()
    np.random.shuffle(X)
    np.random.set_state(rng_state)
    np.random.shuffle(Y)
    return X, Y

'''
Splits datasets where Y has a binary value
'''


def split_data(X, Y, split):
    normal_idx = np.where(Y == 0)
    botnet_idx = np.where(Y == 1)

    X_train = np.concatenate(
        (X[normal_idx][:int(X[normal_idx].shape[0] * (1 - split))],
         X[botnet_idx][:int(X[botnet_idx].shape[0] * (1 - split))]))
    y_train = np.concatenate(
        (Y[normal_idx][:int(Y[normal_idx].shape[0] * (1 - split))],
         Y[botnet_idx][:int(Y[botnet_idx].shape[0] * (1 - split))]))

    X_test = np.concatenate((X[normal_idx][int(X[normal_idx].shape[
                            0] * (1 - split)):], X[botnet_idx][int(len(X[botnet_idx]) * (1 - split)):]))
    y_test = np.concatenate((Y[normal_idx][int(Y[normal_idx].shape[
                            0] * (1 - split)):], Y[botnet_idx][int(Y[botnet_idx].shape[0] * (1 - split)):]))

    return (X_train, y_train), (X_test, y_test)


def save_report(col, data):
    col.insert_one(data)
