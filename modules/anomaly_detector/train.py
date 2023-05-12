import argparse
import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from transformers import BertTokenizer, TFBertForSequenceClassification


def preprocess_data(df):
    # Preprocess the User agent column
    df['User agent'] = df['User agent'].str.extract(r'\(([^\)]*)\)')[0]
    df['User agent'] = df['User agent'].str.split(' ').str[0]

    # Encode the categorical variables
    le = LabelEncoder()
    df['User agent'] = le.fit_transform(df['User agent'])
    df['IP address'] = le.fit_transform(df['IP address'])

    return df


def tokenize_data(data, tokenizer, max_length):
    inputs = tokenizer.batch_encode_plus(
        data,
        add_special_tokens=True,
        max_length=max_length,
        padding='max_length',
        return_attention_mask=True,
        truncation=True
    )
    return np.array(inputs['input_ids']), np.array(inputs['attention_mask'])


def build_model(num_labels):
    model = TFBertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=num_labels)
    model.layers[0].trainable = False
    model.compile(optimizer=tf.keras.optimizers.Adam(lr=2e-5),
                  loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True),
                  metrics=[tf.keras.metrics.SparseCategoricalAccuracy(name='acc')])
    return model


def main(data_path, test_size, max_length, batch_size, epochs, verbose):
    # Load the dataset
    df = pd.read_csv(data_path)

    # Preprocess the dataset
    df = preprocess_data(df)

    # Tokenize the data
    tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
    X_text = df['Text'].values
    X_input_ids, X_attention_masks = tokenize_data(X_text, tokenizer, max_length)

    # Split the data into training and testing sets
    X = np.hstack((df[['User agent', 'IP address']].values, X_input_ids))
    y = df['Label'].values
    X_train, X_test, y_train, y_test, train_masks, test_masks = train_test_split(X, y, X_attention_masks,
                                                                                  test_size=test_size,
                                                                                  random_state=42)

    # Build and train the model
    num_labels = len(np.unique(y_train))
    model = build_model(num_labels)
    history = model.fit([X_train, train_masks], y_train, validation_data=([X_test, test_masks], y_test),
                        batch_size=batch_size, epochs=epochs, verbose=verbose)

    # Predict on the test set
    y_pred = model.predict([X_test, test_masks]).argmax(axis=-1)

    # Print the classification report
    if verbose==1:
        print(classification_report(y_test, y_pred))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--data_path', type=str, default='path/to/dataset.csv', help='Path to the input data file.')
    parser.add_argument('--test_size', type=float, default=0.2, help='Fraction of the dataset to be used for testing.')
    parser.add_argument('--max_length', type=int, default=128, help='Maximum length of input sequence.')
    parser.add_argument('--batch_size', type=int, default=32, help='Batch size for training the model.')
    parser.add_argument('--epochs', type=int, default=5, help='Number of epochs for training the model.')
    parser.add_argument('--verbose', type=int, default=1,help='Verbosity mode. 0 = silent, 1 = printing into command line')
    parser.add_argument
