Models (linear sgd with L1 regularisation) trained in pure slips, NO pipeline (end to end slips training by running training_script.sh if branch jsvobo/mlflow_new_model_testing.
I will devise 2 questions as sanity checks, if my training behaves as I think it should, then several questions regarding the results.


What the results should be dependent on?
Type of model: Linear.
Hyperparameters: L1, otherwise default sklearn
seed: 1111
Zero-mean normalisation
small validation portion (1/10, sometimes small datasets)
Not shuffled before!

What might be a problem?
I acknowledge that these particular results may be the result of the particular seed, randomness and might not reflect the actual similarities between datasets. We didnt check variations between seeds in this part of research.
Linear model is chosen, because it is one of the least complex, learns fast and is well understood.
We didn't cross-validate parameters either, for example alpha for L1 regularisation.
