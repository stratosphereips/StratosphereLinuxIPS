

## Overview
This project provides a modular and scalable **machine learning pipeline** built in **Python** for data preprocessing, model training, evaluation for purpose of offline training models to be used in SLIPS ML modules. The models we are interested in support online learning and are able to be "extended" by partial fit, transfer learning and alike.

### Datasets:
The pipeline works on network flows loaded from zeek dataset with added labels benign and malicious. Other labels are discarded.
The datasets used for testing the pipeline are from https://github.com/stratosphereips/security-datasets-for-testing
Training is done in a similar way to SLIPS. We train model in batches, produce logs with the same structure.
Guide to adding datasets with differnt name and structure to the pipeline is at the end of the README.md

## Parts of the pipeline
- conn_normalizer.py processes conn.log rows by renaming columns, so the names are compatible with slips, filling NaNs, converting to the correct types and adding "established" column.
- features.py is used for filtering and further processing features (dataset columns), e.g. proto to categorical based on hard coded rules.
- dataset_loader.py contains dataset loader, which is given directory, finds every dataset which has conn.log.labeled in it. The wrapper also filters out flows with unwanted labels and caches the result for larger datasets
- logger.py handles where and how training/testing results are written. It calculates metrics from the passed TP,FP,TN,FN
- classifier_wrapper.py and preprocessing_wrapper.py contain class definitions for wrappers of ML models and pre-processing steps. The interface of the classes is
- commons.py contains only enum with classes used in the pipeline
- pipeline.py contains the main ipynb notebook used for training and testing models.

../plot_train_performance.py and ../plot_testing_performance.py are reused from modules/flowmldetection for plotting metrics and summarising results.

## Installation
Create a virtual environment and install dependencies:
Call from modules/flowmldetection/pipeline_ml_training
```bash
    conda create -n slips-ml-pipeline python=3.10 pip
    conda activate slips-ml-pipeline
    pip install -r requirements.txt
```

# Results
After running the pipeline, you'll find directories created with the experiment name in "./logs/(experiment_name)" , "./models/(experiment_name)" and "./results/(experiment_name)" . results/(experiment_name)/ have training and testing directory. Each contains plots and summary of the training/testing runs from different datasets in the same experiment.

# Usage
Steps of training own model, tweaking parameters, specifying train and test datasets.
The pipeline has two conceptional parts. The code used as wrappers and the pipeline itself, which then orchestrates the training/testing, logging etc.
- pipeline.ipynb can be changed if we want to change how batches are processed, what datasets are loaded etc.
- Other files in the directory should be changed to add different classifiers, change which dataset columns are used, feature processing or loging.

### 1. Configure the pipeline
Right now, the configuration is done inside pipeline.ipynb by changing:
- which classes are used for classifier, preprocessing steps,
    - Cell \[4\] in pipeline.ipynb
- seed of the RNG, train/val split
    - Cell \[2\] in pipeline.ipynb
- path to folder with labeled datasets
    - Should begin with XXX which is three-cypher ID of the dataset.
    - Cell \[2\] in pipeline.ipynb
- experiment name
    - Influences where logs, results, models are stored
    - Cell \[2\] in pipeline.ipynb

### 2. Specify commands
In cell \[5\], you can fill a list of commands in a form of \commands = [{},{},{}\]
- keys:
    - "command" --> "train" or "test" , mode of the pipeline
    - "dataset_prefix": --> "008", "009" ... (prefix of the dataset from the loaded set)
    - "validation": --> True, False. To see if we should use train/validation split during the training
If you specify the "test" command first, but the model isnt fitted, the pipeline ends.

### 3. Run the pipeline
In pipeline.ipynb, do "run all" to make sure everything is correctly loaded.
Cell \[6\] runs the train/test loops on datasets specified by the commands list from previous point
Cell \[7\] runs the visualisation scripts on each log produced in the training/testing portion
Cell \[8\] loads the saved model and preprocessing steps as a PoC

### 4. Evaluate results
Model metrics and logs are saved under:
```
./results/<experiment name> with training and testing folders.
./logs/<experiment name> With config.txt and individual logs for each command
```
Output of the logging scripts are visible in the pipeline below cell \[7\]

## Example Output for training
```
=== VALIDATION Multi-class (Aggregated) ===
Benign-Malicious Acc: 0.7990
Malware F1:           0.8875
Malware FPR:          0.9662
Malware FNR:          0.0230
Macro F1:             0.4736
Precision:             0.8130
Recall:                0.9770

=== TRAINING Multi-class (Aggregated) ===
Benign-Malicious Acc: 0.8019
Malware F1:           0.8892
Malware FPR:          0.9636
Malware FNR:          0.0221
Macro F1:             0.4767
Precision:             0.8153
Recall:                0.9779

=== Per-class metrics (Aggregated) - VALIDATION ===
Class                 TP       TN       FP       FN      Acc     Prec      Rec       F1
Benign                42     5221      123     1201   0.7990   0.2545   0.0338   0.0597
Malicious           5221       42     1201      123   0.7990   0.8130   0.9770   0.8875

=== Per-class metrics (Aggregated) - TRAINING ===
Class                 TP       TN       FP       FN      Acc     Prec      Rec       F1
Benign               398    46544     1053    10547   0.8019   0.2743   0.0364   0.0642
Malicious          46544      398    10547     1053   0.8019   0.8153   0.9779   0.8892

Summary for Experiment 4_train_009:
Total batches processed: 159
Data type: Training/Validation split
```

## Example Output for testing
```
=== Main final metrics (Aggregated so-far) ===
Benign-Malicious Acc: 0.7111
Malware F1:           0.8074
Malware FPR:          0.5774
Malware FNR:          0.1927
Macro F1:             0.6149
Precision:            0.8075
Recall:               0.8073

=== Per-class metrics (final snapshot) ===
Class                 TP       TN       FP       FN     Prec      Rec       F1
Malicious           3380      590      806      807   0.8075   0.8073   0.8074
Benign               590     3380      807      806   0.4223   0.4226   0.4225

Summary for Experiment 1_test_008:
Total test lines processed: 6
```

## Extending the Pipeline
#### To add a new model:
If it is sklearn model, see cell \[4\] in **pipeline.ipynb** for code on how to use existing classifier wrapper
We need the model to support "partial fit" or "transfer learning" methods to train batch-by-batch
```
model = SGDClassifier(loss='hinge', penalty='l1',random_state=seed)
classifier = SKLearnClassifierWrapper(model)
```

If your model is not from sklearn, you need to provide an interface
1. Create a new class in `.modules/flowmldetection/pipeline_ml_training/classifier_wrapper.py`. (from Slips base directory)
    - Extend base class 'ClassifierWrapper'
    - Implement the interface of the base class
    - Import this class in pipeline.ipynb
2. In cell \[4\] in **pipeline.ipynb** create a classifier instance to use in the pipeline
    - Call the object classifier

#### Add new preprocessing step:
Use proprocessing from sk-learn.
To add new step of preprocessing, see cell \[4\] in pipeline.ipynb
See code below, provide name of the step and the model.
```
scaler = StandardScaler()
preprocessor = PreprocessingWrapper(experiment_name=experiment_name)
preprocessor.add_step("scaler", scaler)
```
The preprocessing models are saved with the classifier.
Preprocessing steps are executed in order in which they are added.

#### Adding different datasets, loaders
The pipeline works well with our in-house datasets from https://github.com/stratosphereips/security-datasets-for-testing
You can add our loaders in the beginning of the pipeline, then put them into dictionary indexed with 001,002 etc. You'll be then able to use 001, 002 in commands.


## Author
**Jan Svoboda** **Stratosphere Lab**
GitHub: [@jsvobo](https://github.com/jsvobo)
