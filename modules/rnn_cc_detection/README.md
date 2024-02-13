# RNN Command and Control detection for Slips

This is the code of the module plus training programs of the RNN neural network that detects command and control channels in Slips

The model is a GRU RNN

# Run in Slips
This module is loaded by default in Slips. Just be sure it is not disabled in the configuration.

# Training
There is a python file called `training_code/rnn_model_training.py` that can be use to retrain the model.

```bash
python training_code/rnn_model_training.py -v 3 -D datasets/all_datasets_raw -S rnn_model_2024-02-13.h5
```

Once the model is saved in a new file, you can just replace the old one for this one.

```bash
cp rnn_model_2024-02-13.h5 rnn_model.h5
```

# Dataset
The folder `datasets` contain some datasets for trainign a new model. The file you should use is `datasets/all_datasets_raw`.
This file has 7631 outtupples with the ID, label, name and stratoletters. Example:

```bash
[2263] | From-Normal-UDP-DNS--3                                        | 147.32.80.9-147.32.84.131-38302-udp       | 11.R.R.R.R.R.R.R.R.R.R.R.R.R.R.R.R.R.R.R.
```

## Requirementss
* Keras
* Tensorflow/Theano
* Scikit-Learn
* Pandas
