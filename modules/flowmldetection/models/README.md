Linear Model Training
====================================================

Overview
--------
As a beginning of a broader project improving our ML models, we trained 8 different models that can be used in slips.
These models and experimental results will be basis for understanding how models behave on our datasets, with final goal of improving our ML models

Training is executed via:
    orchestration.sh

using script:
    training_script.sh

from the branch:
    jsvobo/mlflow_new_model_testing

Objective
---------
Compare results we achieve using different datasets, store models to be potentially used.

Details
--------
Each model wrained on one datasets from 008 to 015 from our repository: https://github.com/stratosphereips/security-datasets-for-testing
Then each model is evaluated on all used datasets 008-015.
Results are in RESULTS.md , all models are copied into ./classifiers and ./scalers from where this README is located.

Experimental Setup
------------------
Each model is trained only on one model from scratch.

Training Details
- Type: Linear model (SGD with L1 regularization)
- Library: scikit-learn (default parameters unless noted)
- Regularization: L1 (no cross-validation for alpha)
- Seed: 1111
- Normalization: Zero-mean normalization applied
- Validation Split: Small validation subset (typically 1/10)
- Shuffling: Disabled (datasets are not shuffled before training)

- Models are trained directly using slips by orchestration.sh script
- All experiments are reproducible using the provided script and fixed seed.

Expected Dependencies of Results
--------------------------------
Model performance is also influenced by:
- Type of model (linear)
- Regularization (L1)
- Seed (1111)
- Train/validation split ratio (9/1)
- Lack of shuffling prior to training (the flows are loaded as in dataset)

Keep this in mind when evaluating the models.

Potential Issues and Limitations
--------------------------------
- Seed sensitivity: Results may depend on the specific seed (1111). Variations across random seeds have not been explored in this phase.
- Regularization tuning: No cross-validation was performed to optimize hyperparameters.
- Dataset bias: Small validation portions and unshuffled data might cause the model to overfit or underrepresent certain distributions.
- Model simplicity: A linear model might not capture complex relationships present in the data.
