import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2' 
import numpy as np
import argparse
import pandas as pd
import sklearn as sk
import tensorflow as tf
from tensorflow.keras import layers
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
from datetime import datetime
import optuna
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.layers import Dense, Dropout, Input, Reshape
import matplotlib.pyplot as plt
# Author sebastian garcia, eldraco@gmail.com

def get_model_GRU_int_encode (vocabulary_size, embed_dim, first_layer, second_layer, dropout_rate):
    """
    Define and return the model tu use
    """
    model = tf.keras.models.Sequential()
    model.add(layers.Embedding(vocabulary_size, embed_dim, mask_zero=True))
    model.add(layers.Reshape((500, embed_dim)))
    # GRU is the main RNN layer, inputs: A 3D tensor, with shape [batch, timesteps, feature]
    model.add(
        layers.Bidirectional(
            layers.GRU(first_layer, return_sequences=False), merge_mode="concat"
        )
    )
    model.add(layers.Dense(second_layer, activation="relu"))
    model.add(layers.Dropout(dropout_rate))
    model.add(layers.Dense(1, activation="sigmoid"))
    # Fully connected layer with 1 neuron output
    # Final output value between 0 and 1 as probability

    return model



def train():
    """
    Train the model
    """
    # Define Default values
    csvfile = args.dataset_file
    # Less than 5 letters is just too small to know if it is a CC or not. So we set a minimum.
    min_letters = args.min_letters
    # The max 500 letters is arbitrary but we believe that less than 50 letters should be enough to know if it is a CC
    max_letters = args.max_letters
    # In case the sequences are too long to load, is better to never load more than some amount from file to memory. A safeguard
    take_last_num = lambda x: x[: max_letters]

    # Load the dataframe from the TSV file
    df = pd.read_csv(
            csvfile,
            delimiter="|",
            names=["note", "label", "model_id", "state"],
            skipinitialspace=True,
            converters={"state": take_last_num},
        )

    # Clean the dataset
    df.dropna(axis=0, how="any", inplace=True)
    df.drop(axis=1, columns=["note", "model_id"], inplace=True)

    # Delete the strings of letters with less than a certain amount
    indexNames = df[df["state"].str.len() < min_letters].index
    df.drop(indexNames, inplace=True)

    # Add a new column to the dataframe with the label. The label is 'Normal' for the normal data and 'Malcious' for the malware data
    df.loc[df.label.str.contains("Normal"), "label"] = "Normal"
    df.loc[df.label.str.contains("Botnet"), "label"] = "Malicious"
    df.loc[df.label.str.contains("Malware"), "label"] = "Malicious"

    # Encode the label as an integer. 1 for maliciuos, 0 for benign. 
    df.label = df.label.replace("Malicious", 1)
    df.label = df.label.replace("Normal", 0)

    # Convert each of the stratosphere letters to an integer as an encoding. There are 50 symbols
    vocabulary = list("abcdefghiABCDEFGHIrstuvwxyzRSTUVWXYZ1234567890,.+*")
    int_of_letters = {}
    for i, letter in enumerate(vocabulary):
        int_of_letters[letter] = float(i)
    print( f"There are {len(int_of_letters)} letters in total. From letter index {min(int_of_letters.values())} to letter index {max(int_of_letters.values())}.")
    vocabulary_size = len(int_of_letters)

    # Change the letters in the state to an integer representing it uniquely. We 'encode' them.
    df["state"] = df["state"].apply(lambda x: [[int_of_letters[i]] for i in x])
    # So far, only 1 feature per letter
    features_per_sample = 1

    # Convert the data into the appropriate shape
    # x_data is a list of lists. The 1st dimension is the outtuple, the second the letter. Each letter is now an int value. shape=(num_outuples, features_per_sample)
    x_data = df["state"].to_numpy()
    print(f"There are {len(x_data)} outtuples")

    # y_data is a list of ints that are 0 or 1. One integer per outtupple. shape=(num_outuples, 1)
    y_data = df["label"].to_numpy()
    print(f"There are {len(y_data)} labels")

    # Here x_data is a array of lists [[]]
    print(f"x_data type {type(x_data)} of shape {x_data.shape}. x_data[0] type is {type(x_data[0])}")
    print(f"x_data[0] is {x_data[0]}")

    # Search the sample with max len in the training. It should be already cuted by the csv_read function to a max. Here we just check
    max_length_of_outtupple = max([len(sublist) for sublist in df.state.to_list()])
    print(f"The max len of the letters in all outtuples is: {max_length_of_outtupple}")

    # Padding.
    # Since not all outtuples have the same amount of letters, we need to add padding at the end
    # Transforms the list to a 2D Numpy array of shape (num_samples, num_timesteps)
    # num_timesteps is either the maxlen argument if provided, or the length of the longest sequence otherwise.
    # Sequences that are shorter than num_timesteps are padded with value at the end.
    # padding: 'pre' or 'post': pad either before or after each sequence.
    # truncating: 'pre' or 'post': remove values from sequences larger than maxlen, either at the beginning or at the end of the sequences.

    # If the input are integers
    padded_x_data = pad_sequences(
        x_data, maxlen=max_length_of_outtupple, padding="post"
    )
    print(
            f"Padded_x_data is of type {type(padded_x_data)}, of shape {padded_x_data.shape}. padded_x_data[0] type is {type(padded_x_data[0])}. Shape of second list is {padded_x_data[0].shape}"
        )

    # Split the data in training/evaluation and testing
    x_data = padded_x_data
    y_data = y_data

    X_traineval, X_test, y_traineval, y_test = train_test_split(x_data, y_data, test_size=0.2, random_state=42)

    # number_of_outtuples in general
    num_outtuples = X_traineval.shape[0]  

    # In the case of hot-encoding, the amount of features per letter per sample, is 50, which is the vocabulary size
    # features_per_sample = vocabulary_size # amount of positions of the hot encoding (50 letters, so 50)
    # print(f'We have as input shape: {num_outtuples}, {max_length_of_outtupple}, {features_per_sample}')
    # input_shape = (num_outtuples, features_per_sample)

    # In the case of not using hot-encoding, the amount of features per sample is 1, because we only have one value
    # The amount of time steps is the amount of letters, since one letter is one time step, which is the amount of letters max, which 500
    input_shape = (num_outtuples, features_per_sample)
    print(
        f"We have as shape: Num of samples in train/eval: {num_outtuples}, Num of letters per sample (timesteps): {max_length_of_outtupple}, each letter has {features_per_sample} values. The input shape is {input_shape}"
    )

    input_data = Input(shape=(500, 1, 64))
    reshaped_input = Reshape((500, 64))(input_data)

    # Model being explored. Used for file name creation.
    model_trained = args.model_version

    # Get current date
    model_train_date = datetime.now().strftime('%Y-%m-%d')

    if args.optuna:
        # Use optuna
        print('Using optuna to find best parameters')

        # Define objective function
        def objective(trial):

            # Here is where you define the ranges of hyperparameters to optimize
            learning_rate = trial.suggest_float("learning_rate", 1e-5, 1e-2, log=True)
            dropout_rate = trial.suggest_float("dropout_rate", 0.0, 0.6)
            embed_dim = trial.suggest_int("embedded_dim", 8, 128)
            first_layer = trial.suggest_categorical('firstlayer', [8, 16, 20, 24, 28, 32, 36])
            second_layer = trial.suggest_categorical('second_layer', [16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72])

            log = f'Trial: {trial}. Trying lr:{learning_rate}, drop:{dropout_rate}, embed:{embed_dim}, 1st lay: {first_layer}, 2nd lay: {second_layer}'
            print(log)
            
            # Load dataset
            X_traineval, X_test, y_traineval, y_test = train_test_split(x_data, y_data, test_size=0.2, random_state=42)    
            print(f'X_traineval shape: {X_traineval.shape}, X_test shape: {X_test.shape}, y_traineval shape: {y_traineval.shape}, y_test shape: {y_test.shape}')
            
            # Create the model of RNN
            model = get_model_GRU_int_encode(vocabulary_size, embed_dim, first_layer, second_layer, dropout_rate)
            
            # Compile model
            model.compile(optimizer=Adam(learning_rate=learning_rate, beta_1=0.9, beta_2=0.999),
                        loss='binary_crossentropy',
                        metrics=['accuracy'])
            
            # Train model
            # We only search optimizations in 30 episodes, since that seems to be enough to find good ones
            model.fit(X_traineval, y_traineval, validation_data=(X_traineval, y_traineval), epochs=30, batch_size=100, verbose=1)
            
            # Evaluate model
            val_loss, val_acc = model.evaluate(X_test, y_test, verbose=0)

            log = f'\tVal_acc: {val_acc}. Val_loss: {val_loss}'
            print(log)

            return val_acc

        # Set up Optuna study
        study = optuna.create_study(direction="maximize")
        study.optimize(objective, n_trials=500)

        # Get best hyperparameters
        best_params = study.best_params
        print("Best hyperparameters:", best_params)


        logfile = open('training_model.log', 'w+')
        log = f'Best hyperparameters: {best_params}'
        print(log)
        logfile.write(log)
        logfile.close()

    elif not args.optuna:
        print('Training the model with good hyperparameters')
        # Now that you now the Hyperparameters, you can train a larger model
        embed_dim = args.embed_dim
        print(f'X_traineval shape: {X_traineval.shape}, X_test shape: {X_test.shape}, y_traineval shape: {y_traineval.shape}, y_test shape: {y_test.shape}. Embed_dim: {embed_dim}')

        # Create the model of RNN
        model = tf.keras.models.Sequential()
        model.add(layers.Embedding(vocabulary_size, embed_dim, mask_zero=True))
        # GRU is the main RNN layer, inputs: A 3D tensor, with shape [batch, timesteps, feature]
        # Change the first layer too
        model.add(layers.Reshape((500, embed_dim)))
        model.add(
            layers.Bidirectional(
                layers.GRU(32, return_sequences=False), merge_mode="concat"
            )
        )
        # Change the second layer too
        model.add(layers.Dense(32, activation="relu"))
        model.add(layers.Dropout(args.dropout))
        # Fully connected layer with 1 neuron output
        # Final output value between 0 and 1 as probability
        model.add(layers.Dense(1, activation="sigmoid"))

        # Compile model
        model.compile(optimizer=Adam(learning_rate=args.lr, beta_1=0.9, beta_2=0.999),
                    loss='binary_crossentropy',
                    metrics=['accuracy'])
        
        # Train the model
        # This is already separating in trainign and validation

        num_epochs = args.epochs
        batch_size = args.batch_size
        print(f'Training the model with {num_epochs} epochs and {batch_size} batch size.')

        history = model.fit(
            X_traineval,
            y_traineval,
            epochs=num_epochs,
            batch_size=batch_size,
            validation_split=0.1,
            verbose=1,
            shuffle=True,
        )

        if args.model_file:
            model_outputfile = args.model_file
        else:
            model_outputfile = f'rnn_model_{model_trained}_2024-04-20.h5'
        print(model.summary())
        #model.save(model_outputfile, overwrite=False)
        keras.saving.save_model(model, model_outputfile)
        
        # Plots
        # To plot the results of training

        acc = history.history["accuracy"]
        val_acc = history.history["val_accuracy"]
        loss = history.history["loss"]
        val_loss = history.history["val_loss"]
        epochs = range(1, len(acc) + 1)
        plt.plot(epochs, acc, "ro", label="Training acc")
        plt.plot(epochs, val_acc, "r", label="Validation acc")

        plt.title("Training and validation accuracy")
        plt.legend()
        plt.savefig(f"rnn_model_{model_trained}-{model_train_date}.acc.png")

        plt.close()
        plt.plot(epochs, loss, "bo", label="Training loss")
        plt.plot(epochs, val_loss, "b", label="Validation loss")
        plt.title("Training and validation loss")
        plt.legend()
        plt.savefig(f"rnn_model_{model_trained}-{model_train_date}.loss.png")

        # Evaluate model on the new dataset
        loss, accuracy = model.evaluate(X_test, y_test)

        # Print evaluation results
        print("Test Generatilization Results:")
        print("Test Loss:", loss)
        print("Test Accuracy:", accuracy)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-D",
        "--dataset_file",
        help="File containing data for training",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-l",
        "--lr",
        help="Learning rate",
        type=float,
        default=0.00189621996231622,
        required=False
    )
    parser.add_argument(
        "-i",
        "--embed_dim",
        help="Embedding dimension",
        type=int,
        default=64,
        required=False
    )
    parser.add_argument(
        "-d",
        "--dropout",
        help="Percentage of dropout",
        type=float,
        default=0.34,
        required=False
    )
    parser.add_argument(
        "-M",
        "--max_letters",
        help="Max sequence length",
        type=int,
        required=False,
        default=500,
    )
    parser.add_argument(
        "-m",
        "--min_letters",
        help="Min sequence length",
        type=int,
        required=False,
        default=5,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Level of verbosity",
        type=bool,
        required=False,
        default=False,
    )
    parser.add_argument(
        "-b",
        "--batch_size",
        help="Size of the minibatch",
        type=int,
        required=False,
        default=100,
    )
    parser.add_argument(
        "-e",
        "--epochs",
        help="Number of epochs in training",
        type=int,
        required=False,
        default=200,
    )
    parser.add_argument(
        "-S",
        "--model_file",
        help="Where to store the train model",
        type=str,
        required=False,
    )
    parser.add_argument(
        "-o",
        "--optuna",
        help="Use optuna to find best hyperparameters",
        action='store_true',
        default=False,
        required=False,
    )
    parser.add_argument(
        "-V",
        "--model_version",
        help="String of the model version. Used for files",
        type=str,
        required=True,
    )
    args = parser.parse_args()

    print('\nTraining the NN model for C&C detection for Slips.')
    # Versions
    print(f"Numpy: {np.__version__}")
    print(f"TensorFlow: {tf.__version__}")
    print(f"Pandas: {pd.__version__}")
    print(f"Sklearn: {sk.__version__}")

    train()
