#!/usr/bin/env python3
import sys
import numpy as np
import pandas as pd
from sklearn import metrics
from sklearn.model_selection import train_test_split
from random import shuffle

from keras.models import Sequential
from keras.layers.core import Dense, Activation, Masking, Dropout
from keras.layers.embeddings import Embedding
from keras.layers.recurrent import GRU
from keras.callbacks import ModelCheckpoint
from keras.preprocessing.sequence import pad_sequences
from keras.preprocessing.text import one_hot
from keras.models import load_model
from datetime import datetime

dataset_file='datasets/all_datasets_raw'
# Cut the max amount of letters in the state to a maximum. 
# Better here so we dont use memory
max_letters = 500
f = lambda x: x[:max_letters]
with open(dataset_file, 'rb') as csvfile:
    df = pd.read_csv(csvfile, delimiter='|', names=[ "note", "label", "model_id", "state"], skipinitialspace=True, converters={'state': f} )

# Clean the dataset
df.dropna(axis=0, how='any', inplace=True) 
df.drop(axis=1, columns=['note', 'model_id'], inplace=True)

def filter_by_string(df, col, string):
    ''' A function to filter the columns and rows'''
    return df[df[col].str.contains(string, regex=False) == True]

# Add a new column to the dataframe with the label. The label is 'Normal' for the normal data and 'Malcious' for the malware data
df.loc[df.label.str.contains('Normal'),'label'] = 'Normal'
df.loc[df.label.str.contains('Botnet'),'label'] = 'Malicious'
df.loc[df.label.str.contains('Malware'),'label'] = 'Malicious'

# Change the labels from Malicious/Normal to 1/0 integers in the df
df.label.replace('Malicious', 1, inplace=True)
df.label.replace('Normal', 0, inplace=True)

# Change the letters in the state to their ASCII values
df['state'] = df['state'].apply(lambda x : [ord(i) for i in x])

# Convert the data into the appropriate shape
# x_data is a list of lists. The 1st dimension is the outtuple, the second the letter. Each letter is now an int value. shape=(num_outuples, features_per_sample)
x_data = df['state'].to_list()
print('There are {} outtuples'.format(len(x_data)))
# y_data is a list of ints that are 0 or 1. One integer per outtupple. shape=(num_outuples, 1)
y_data = df['label'].to_list()
print('There are {} labels'.format(len(y_data)))
# Search the sample with max len in the training. It should be already cuted by the csv_read function to a max. Here we just check
max_length = max([len(sublist) for sublist in df.state.to_list()])
print('The max len of the letters in all outtuples is: {}'.format(max_length))


# Padding.
# Since not all outtuples have the same amount of letters, we need to add padding at the end
# Transforms the list to a 2D Numpy array of shape (num_samples, num_timesteps)
# num_timesteps is either the maxlen argument if provided, or the length of the longest sequence otherwise.
# Sequences that are shorter than num_timesteps are padded with value at the end.
# padding: 'pre' or 'post': pad either before or after each sequence.
# truncating: 'pre' or 'post': remove values from sequences larger than maxlen, either at the beginning or at the end of the sequences.

padded_x_data = pad_sequences(x_data, maxlen=max_length, padding='post')


# Split the data in training and testing
#train_data, test_data = train_test_split(df, test_size=0.2, shuffle=True)

# For now, just use all the data
train_x_data = padded_x_data
train_y_data = y_data


# Change the number for each experiment
experiment_number = '10'
f = open('data_for_experiment_' + experiment_number + '.md', 'w+')
f.write('Summary of Experiment Number ' + experiment_number + '\n')
f.write('Date: ' + str(datetime.now()) + '\n\n')

# Hyperparameters
# Real data
# Store the dimensions
batch_size = 500 # group of outtuples as a batch
num_outtuples = len(padded_x_data) # number_of_outtuples in each batch or in general?
features_per_sample = max_length # # letters per outputple
num_epochs = 5 
# Max value of all ord(letter)
max_ord_value = max([max(sublist) for sublist in x_data]) + 1
# Each letter can be a number from 41 (a) to 122 (z)

# Write
f.write('Batch size: ' + str(batch_size) + '\n')
f.write('Num outtuples: ' + str(num_outtuples) + '\n')
f.write('Max num of letters: ' + str(features_per_sample) + '\n')
f.write('Num epochs: ' + str(num_epochs) + '\n')


# Create the model of RNN
input_shape = (num_outtuples, features_per_sample)
model = Sequential()
# Masking adds a padding and a special vector to ignore the padding values.
#model.add(Masking(input_shape = input_shape, mask_value = 0.0))
model.add(Embedding(max_ord_value, 500, input_length=features_per_sample))
# GRU is the main RNN layer
model.add(GRU(256, return_sequences=True, input_shape=(num_outtuples, features_per_sample)))
model.add(GRU(512, return_sequences=False, input_shape=(num_outtuples, features_per_sample)))
# Fully connected layer with 1 neuron output
model.add(Dense(1))
# Final output value between 0 and 1 as probability
model.add(Activation('sigmoid'))
model.compile(loss='binary_crossentropy', optimizer = 'rmsprop', metrics=['accuracy'])

# Write

# Train the model
# This is already separating in trainign and validation
history = model.fit(train_x_data, train_y_data, epochs=num_epochs, batch_size=batch_size, validation_split=0.3, verbose=1, shuffle=True)
f.write('Model Summary: ' + str(num_epochs) + '\n')
f.write(str(model.summary()))
f.write('\n\n')

f.write('Model last results\n')
f.write('\tTraining Accuracy: ' + str(history.history['acc'][-1]) + '\n')
f.write('\tTraining Loss: ' + str(history.history['loss'][-1]) + '\n')
f.write('\tValidation Accuracy: ' + str(history.history['val_acc'][-1]) + '\n')
f.write('\tValidation Loss: ' + str(history.history['val_loss'][-1]) + '\n')
f.close()

# Save the model to disk
model.save('lstm_model-e' + experiment_number +'.h5')

# To plot the results

import matplotlib.pyplot as plt
acc = history.history['acc']
val_acc = history.history['val_acc']
loss = history.history['loss']
val_loss = history.history['val_loss']
epochs = range(1, len(acc) + 1)
plt.plot(epochs, acc, 'bo', label='Training acc')
plt.plot(epochs, val_acc, 'b', label='Validation acc')

plt.title('Training and validation accuracy')
plt.legend()
plt.figure()
plt.plot(epochs, loss, 'bo', label='Training loss')
plt.plot(epochs, val_loss, 'b', label='Validation loss')
plt.title('Training and validation loss')
plt.legend()
#plt.show()

plt.savefig('plot_e_' + experiment_number + '.png')








