> The default detector is now the numeric `beaconing` module. See
> [its documentation](../../docs/beaconing.md) for configuration, measured results
> and limitations. This legacy RNN is disabled in the default configuration.
> Runtime preprocessing and state handling were repaired, but the historical
> metrics below do not represent independent C2 validation. Retraining now requires
> explicit C2 labels and disjoint capture groups; use the module command documented
> in `docs/beaconing.md`, for the current training command.

# RNN Command and Control detection for Slips
This is the code of the module plus training programs of the RNN neural network that detects command and control channels in Slips.

There are several models that we have been trying. Each model is documented here with a version number and training performance.

# Who gets alerted
The C&C alert from this module is used to alert on the __source__ of the connection, and also the __destination__ of the connection.

# Machine Learning models

## v1. Embedding + GRU
The first ML model we implemened is v1. It is a bidirectional GRU network.

### Features
- Each letter is encoded to an integer.
- All 4-tuples have a max length of 500 letters.
- All 4-tuples are padded to have the same length. Pad is done with integer 0.

### Model
- One embedding layer that converts each 'integer token' into a vector of dimensionality 16.
- A bidirectional GRU layer with 32 inputs/units. Using `return_sequences=False` to indicate that the layer should only return the output of the GRU at the last time step instead of the full sequence of outputs.
- A dense FF layer of 32 units with Relu activation.
- A dropout layer with 0.5 change of dropout
- An output layer with 1 unit and sigmoid activation.
- Model compiled with crossentropy and RMSprop optimizer. Learning rate 0.0001 and momentum 0.05, and metric accuracy.

The summary is

        Model: "sequential"
        _________________________________________________________________
        Layer (type)                Output Shape              Param #
        =================================================================
        embedding (Embedding)       (None, None, 16)          800

        bidirectional (Bidirection  (None, 64)                9600
        al)

        dense (Dense)               (None, 32)                2080

        dropout (Dropout)           (None, 32)                0

        dense_1 (Dense)             (None, 1)                 33

        =================================================================
        Total params: 12513 (48.88 KB)
        Trainable params: 12513 (48.88 KB)
        Non-trainable params: 0 (0.00 Byte)

### Train Performance

The final train performance after 100 epochs is:

train_loss: 0.1652
val_loss: 0.4539
train_accuracy: 0.9322
val_accuracy: 0.8296

![Acc](docs/rnn_model_v1_2024-04-20.acc.png)
![Loss](docs/rnn_model_v1_2024-04-20.loss.png)

![Stratosphere Linux IPS (Slips) - Frame 1](https://github.com/stratosphereips/StratosphereLinuxIPS/assets/2458867/eba4021a-4c54-4523-9380-fb179526d808)

### Test Performance
        Test Loss: 0.17785538733005524
        Test Accuracy: 0.926008939743042



---
## v1.1 Embedding + GRU
Same as model v1 but with better separation of train and evaluation datasets, the new test dataset and the use of an embedding layer.

## Train performance
loss: 0.2159 - accuracy: 0.9089 - val_loss: 0.2114 - val_accuracy: 0.8994

![Acc](docs/rnn_model_v1.1-2024-04-20.acc.png)
![Loss](docs/rnn_model_v1.1-2024-04-20.loss.png)

## Test performance
        Test Loss: 0.2069242298603058
        Test Accuracy: 0.9035874605178833


---
## v1.2 Embedding + GRU
Same as v1 but with different hyperparameters found by optuna.


        Model: "sequential"
        _________________________________________________________________
        Layer (type)                Output Shape              Param #
        =================================================================
        embedding (Embedding)       (None, None, 64)          3200

        bidirectional (Bidirection  (None, 64)                18816
        al)

        dense (Dense)               (None, 32)                2080

        dropout (Dropout)           (None, 32)                0

        dense_1 (Dense)             (None, 1)                 33

        =================================================================
        Total params: 24129 (94.25 KB)
        Trainable params: 24129 (94.25 KB)

## Training

Found hyperparameters with optuna

        # Best hyperparameters: {'learning_rate': 0.001896219962316226, 'dropout_rate': 0.3405832906149749, 'momentum_rate': 0.05593281020818976, 'embedded_dim': 64}


![Acc](docs/rnn_model_v1.2-2024-04-21.acc.png)
![Loss](docs/rnn_model_v1.2-2024-04-21.loss.png)

## Testing
        Test Loss: 1.2258477210998535
        Test Accuracy: 0.9304932951927185


---
# v1.3 Embedding + GRU
A test model that was rapidly superseded



---
# v.1.4 Embedding + GRU
As v1, but more optimization with optuna.

         Layer (type)                Output Shape              Param #
        =================================================================
         embedding (Embedding)       (None, None, 60)          3000

         bidirectional (Bidirection  (None, 64)                18048
         al)

         dense (Dense)               (None, 32)                2080

         dropout (Dropout)           (None, 32)                0

         dense_1 (Dense)             (None, 1)                 33

        =================================================================

Total params: 23161 (90.47 KB)
Trainable params: 23161 (90.47 KB)
Non-trainable params: 0 (0.00 Byte)

## Training

![Acc](docs/rnn_model_v1.4-2024-04-23.acc.png)
![Loss](docs/rnn_model_v1.4-2024-04-23.loss.png)


## Testing
        Test Loss: 0.5616011023521423
        Test Accuracy: 0.939461886882782


---
# v.1.5 Embedding + GRU
As v1, with more optimization with optuna (500 searches) and trained on Docker on Linux for python 3.10.12. This model works in Docker for Linux and Docker for macos M1.

## Training
Model: "sequential"

        ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
        ┃ Layer (type)                         ┃ Output Shape                ┃         Param # ┃
        ┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
        │ embedding (Embedding)                │ (None, 500, 1, 94)          │           4,700 │
        ├──────────────────────────────────────┼─────────────────────────────┼─────────────────┤
        │ reshape_1 (Reshape)                  │ (None, 500, 94)             │               0 │
        ├──────────────────────────────────────┼─────────────────────────────┼─────────────────┤
        │ bidirectional (Bidirectional)        │ (None, 32)                  │          10,752 │
        ├──────────────────────────────────────┼─────────────────────────────┼─────────────────┤
        │ dense (Dense)                        │ (None, 24)                  │             792 │
        ├──────────────────────────────────────┼─────────────────────────────┼─────────────────┤
        │ dropout (Dropout)                    │ (None, 24)                  │               0 │
        ├──────────────────────────────────────┼─────────────────────────────┼─────────────────┤
        │ dense_1 (Dense)                      │ (None, 1)                   │              25 │
        └──────────────────────────────────────┴─────────────────────────────┴─────────────────┘
 Total params: 48,809 (190.66 KB)
 Trainable params: 16,269 (63.55 KB)
 Non-trainable params: 0 (0.00 B)
 Optimizer params: 32,540 (127.11 KB)

## Testing
        Test Loss: 0.47594040632247925
        Test Accuracy: 0.9304932951927185

![Acc](docs/rnn_model_v1.5-2024-07-13.acc.png)
![Loss](docs/rnn_model_v1.5-2024-07-13.loss.png)






---

# Training replacement models

Use the reviewed-data workflow in [docs/beaconing.md](../../docs/beaconing.md).
The trainer requires TSV columns `group`, `split`, `label`, `state`; labels must
be `benign` or `c2`. Keep independent captures in separate training, validation
and test groups. Broad Botnet/Malware labels are not automatically C2 labels.

```bash
python -m modules.rnn_cc_detection.training_code.train_optimization_optuna \
  -D reviewed-labels.tsv -S output/beaconing/rnn_model.h5 --epochs 30 --trials 10
```

The replacement reserves token zero for padding and writes matching encoding
metadata beside the model. Deploy the `.h5` and `.h5.json` together after
independent evaluation. The existing `.h5` remains on its legacy token map.

# Archived dataset

`datasets/all_datasets_raw.tsv` contains 7,631 historical labeled letter
sequences. Its broad labels include non-C2 malware activity, and some encoded
inputs are duplicated or have conflicting labels. It is not a reviewed C2
training manifest and is rejected by the replacement trainer. Preserve it for
research; curate explicit connection labels and capture groups before reuse.

# Stratosphere Letters
Slips detects network behaviors. The behavior is represented by how a specific user interacts with a specific service, and is more than just connections or flows. The behavior is constructed by getting together all the flows that share 4 pieces of data: `source IP`, `destination IP`, `destination port`, and `protocol`. It ignores the source port. This aggregation is called an `4-tuple`.

For each `4-tuple` this module analyzes the `periodicity`, `size` and `duration` of each flow (the periodicity is a ratio computed by three consecutive flows, see the code).

These features are then discretized in ranges of values so to avoid work with continual variables. The size can be `small`, `medium` or `large`, the duration `short`, `medium`, or `long`, the periodicity `strong periodicty`, `weak periodicity`, `weak non-periodicity`, `strong non-periodicity` or `no data` (no data for when there are not still three flows minimum to compute it). Each combination of `size`, `duration` and `frequency` is assigned an ASCII symbol that uniquely represents the combination. See Figure 1.

Betwee the letters, symbols are added to represent the absolute time passed, since it is not the same to have a strong periodicty of 1 second, that one of 1 day.
- `.`: Time between the last two flows was between 0 and 5 seconds.
- `,`: Time between the last two flows was between 5 and 60 seconds.
- `+`: Time between the last two flows was between 60 and 5 minutes.
- `*`: Time between the last two flows was between 5 minutes and 1 hour.
- `0`: Time between the last two flows was more than 1 hour and it is considered a timeout. Meaning there can be many `0` together.

![Stratosphere Linux IPS (Slips) - Frame 1](https://github.com/stratosphereips/StratosphereLinuxIPS/assets/2458867/eba4021a-4c54-4523-9380-fb179526d808)

Figure 1

For example, the connection identified with the 4-tuple `192.168.0.253-166.78.144.80-80-tcp`, may have the following behavioral model:

88*y*y*i*H*H*H*y*0yy*H*H*H*y*y*y*y*H*h*y*h*h*H*H*h*H*y*y*y*H*

This chain of states that we call the `behavioral model` highlight some of the characteristics of the C&C channel. In this case it tell us that flows are highly periodic (letters ‘h’, ‘i’), with some lost periodicity near the beginning (letters ‘y’). The flows also have a large size with a medium duration.

Looking at the letters it can be seen that this is a rather periodic connection, and effectively checking its flows we confirm that hypothesis. Using these type of models we are able to generate the behavioral characteristics of a large number of malicious actions.

The legacy RNN classifies TCP only. The numeric `beaconing` module also reports
UDP periodicity; its shipped C2 classifier is trained on TCP examples.
