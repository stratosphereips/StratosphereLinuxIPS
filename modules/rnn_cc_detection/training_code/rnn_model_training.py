import sys
import numpy as np
import pandas as pd
import argparse
from sklearn import metrics
from sklearn.model_selection import train_test_split
from random import shuffle

import tensorflow as tf
import sklearn as sk
from tensorflow.keras import layers
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import one_hot
from tensorflow.keras.models import load_model
from tensorflow.keras.utils import to_categorical

parser = argparse.ArgumentParser()
parser.add_argument(
    '-D',
    '--dataset_file',
    help='File containing data for training',
    type=str,
    required=True,
)
parser.add_argument(
    '-M',
    '--max_letters',
    help='Max sequence length',
    type=int,
    required=False,
    default=500,
)
parser.add_argument(
    '-m',
    '--min_letters',
    help='Min sequence length',
    type=int,
    required=False,
    default=5,
)
parser.add_argument(
    '-v',
    '--verbose',
    help='Level of verbosity',
    type=bool,
    required=False,
    default=False,
)
parser.add_argument(
    '-b',
    '--batch_size',
    help='Size of the minibatch',
    type=int,
    required=False,
    default=100,
)
parser.add_argument(
    '-e',
    '--epochs',
    help='Number of epochs in training',
    type=int,
    required=False,
    default=200,
)
parser.add_argument(
    '-S',
    '--model_file',
    help='Where to store the train model',
    type=str,
    required=False,
)
args = parser.parse_args()


if args.verbose:
    # Versions
    print(f'Numpy: {np.__version__}')
    print(f'TensorFlow: {tf.__version__}')
    print(f'Pandas: {pd.__version__}')
    print(f'Sklearn: {sk.__version__}')

# Load the dataset
# Cut the max amount of letters in the state to a maximum.
# Better to do it here in the read_csv so we dont use memory later. Here those lines never go into memory.
f = lambda x: x[: args.max_letters]
with open(args.dataset_file, 'rb') as csvfile:
    df = pd.read_csv(
        csvfile,
        delimiter='|',
        names=['note', 'label', 'model_id', 'state'],
        skipinitialspace=True,
        converters={'state': f},
    )

if args.verbose:
    df.describe()


# Clean the dataset
df.dropna(axis=0, how='any', inplace=True)
df.drop(axis=1, columns=['note', 'model_id'], inplace=True)

# Delete the strings of letters with less than a certain amount
indexNames = df[df['state'].str.len() < args.min_letters].index
df.drop(indexNames, inplace=True)


# Add a new column to the dataframe with the label. The label is 'Normal' for the normal data and 'Malcious' for the malware data
df.loc[df.label.str.contains('Normal'), 'label'] = 'Normal'
df.loc[df.label.str.contains('Botnet'), 'label'] = 'Malicious'
df.loc[df.label.str.contains('Malware'), 'label'] = 'Malicious'

# Change the labels from Malicious/Normal to 1/0 integers in the df
df.label.replace('Malicious', 1, inplace=True)
df.label.replace('Normal', 0, inplace=True)


# Convert each of the stratosphere letters to an integer. There are 50
vocabulary = list('abcdefghiABCDEFGHIrstuvwxyzRSTUVWXYZ1234567890,.+*')
int_of_letters = {}
for i, letter in enumerate(vocabulary):
    int_of_letters[letter] = float(i)
if args.verbose:
    print(
        f'There are {len(int_of_letters)} letters in total. From letter index {min(int_of_letters.values())} to letter index {max(int_of_letters.values())}.'
    )
vocabulary_size = len(int_of_letters)


# Change the letters in the state to an integer representing it uniquely. We 'encode' them.
df['state'] = df['state'].apply(lambda x: [[int_of_letters[i]] for i in x])
# So far, only 1 feature per letter
features_per_sample = 1


# Convert the data into the appropriate shape
# x_data is a list of lists. The 1st dimension is the outtuple, the second the letter. Each letter is now an int value. shape=(num_outuples, features_per_sample)
x_data = df['state'].to_numpy()
if args.verbose:
    print(f'There are {len(x_data)} outtuples')
# y_data is a list of ints that are 0 or 1. One integer per outtupple. shape=(num_outuples, 1)
y_data = df['label'].to_numpy()
if args.verbose:
    print(f'There are {len(y_data)} labels')
# Search the sample with max len in the training. It should be already cuted by the csv_read function to a max. Here we just check
max_length_of_outtupple = max([len(sublist) for sublist in df.state.to_list()])
if args.verbose:
    print(
        f'The max len of the letters in all outtuples is: {max_length_of_outtupple}'
    )

# Here x_data is a array of lists [[]]
if args.verbose:
    print(
        f'x_data type {type(x_data)} of shape {x_data.shape}. x_data[0] type is {type(x_data[0])}'
    )
    print(f'x_data[0] is {x_data[0]}')


# Padding.
# Since not all outtuples have the same amount of letters, we need to add padding at the end
# Transforms the list to a 2D Numpy array of shape (num_samples, num_timesteps)
# num_timesteps is either the maxlen argument if provided, or the length of the longest sequence otherwise.
# Sequences that are shorter than num_timesteps are padded with value at the end.
# padding: 'pre' or 'post': pad either before or after each sequence.
# truncating: 'pre' or 'post': remove values from sequences larger than maxlen, either at the beginning or at the end of the sequences.

# If the input is a string
# padded_x_data = pad_sequences(x_data, maxlen=max_length_of_outtupple, padding='post', value='0', dtype=object )

# If the input are integers
padded_x_data = pad_sequences(
    x_data, maxlen=max_length_of_outtupple, padding='post'
)
if args.verbose:
    print(
        f'padded_x_data is of type {type(padded_x_data)}, of shape {padded_x_data.shape}. padded_x_data[0] type is {type(padded_x_data[0])}. Shape of second list is {padded_x_data[0].shape}'
    )


# Split the data in training and testing
# train_data, test_data = train_test_split(df, test_size=0.2, shuffle=True)

# For now, just use all the data

# Split the one-hot
# train_x_data = x_data_oh
# train_y_data = y_data

# Split the padded data only without one-hot
train_x_data = padded_x_data
train_y_data = y_data


# Hyperparameters
# Real data
# Store the dimensions
# batch_size = 100 # group of outtuples as a batch
num_outtuples = train_x_data.shape[0]   # number_of_outtuples in general
# max_length_of_outtupple # max amount of letters in each outtuple (500 now)

# In the case of hot-encoding, the amount of features per letter per sample, is 50, which is the vocabulary size
# features_per_sample = vocabulary_size # amount of positions of the hot encoding (50 letters, so 50)
# print(f'We have as input shape: {num_outtuples}, {max_length_of_outtupple}, {features_per_sample}')
# input_shape = (max_length_of_outtupple, features_per_sample)

# In the case of not using hot-encoding, the amount of features per sample is 1, because we only have one value
# The amount of time steps is the amount of letters, since one letter is one time step, which is the amount of letters max, which 500
timesteps = max_length_of_outtupple
input_shape = (timesteps, features_per_sample)
print(
    f'We have as shape: Num of samples: {num_outtuples}, Num of letters per sample (timesteps): {timesteps}, each letter has {features_per_sample} values. The input shape is {input_shape}'
)

# num_epochs = 500

# The shape of the input is now : (2200, 500, 50)
# 2200, amount of outtuples
# 500, is the padded amount of letters in each outtuple
# 50, the one hot on the amount of letters


# Create the model of RNN
model = tf.keras.models.Sequential()
model.add(layers.Embedding(vocabulary_size, 16, mask_zero=True))
# GRU is the main RNN layer, inputs: A 3D tensor, with shape [batch, timesteps, feature]
model.add(
    layers.Bidirectional(
        layers.GRU(32, return_sequences=False), merge_mode='concat'
    )
)
model.add(layers.Dense(32, activation='relu'))
model.add(layers.Dropout(0.5))
model.add(layers.Dense(1, activation='sigmoid'))
# Fully connected layer with 1 neuron output
# Final output value between 0 and 1 as probability
model.compile(
    loss='binary_crossentropy',
    optimizer=tf.keras.optimizers.RMSprop(learning_rate=0.0001, momentum=0.05),
    metrics=['accuracy'],
)


# Train the model
# This is already separating in trainign and validation
history = model.fit(
    train_x_data,
    train_y_data,
    epochs=args.epochs,
    batch_size=args.batch_size,
    validation_split=0.1,
    verbose=1,
    shuffle=True,
)

if args.verbose:
    model.summary()
model.save(args.model_file, overwrite=False)

# To plot the results
import matplotlib.pyplot as plt

acc = history.history['accuracy']
val_acc = history.history['val_accuracy']
loss = history.history['loss']
val_loss = history.history['val_loss']
epochs = range(1, len(acc) + 1)
plt.plot(epochs, acc, 'ro', label='Training acc')
plt.plot(epochs, val_acc, 'r', label='Validation acc')

plt.title('Training and validation accuracy')
plt.legend()
plt.savefig('test_results_acc.png')

plt.close()
plt.plot(epochs, loss, 'bo', label='Training loss')
plt.plot(epochs, val_loss, 'b', label='Validation loss')
plt.title('Training and validation loss')
plt.legend()
plt.savefig('test_results_loss.png')
