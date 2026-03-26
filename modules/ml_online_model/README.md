# `ml_online_model` (user guide)

This module provides a River-based flow model for SLIPS.

## Runtime artifacts

- `modules/ml_online_model/artifacts/model.bin`
- `modules/ml_online_model/artifacts/scaler.bin`


## Train/test (module-specific)

Canonical workflow is in `slips_files/common/abstracts/README.md`.

`ml_online_model`-specific paths:

- original test load:
  - `model_load_path: modules/ml_online_model/artifacts/model.bin`
  - `preprocess_load_path: modules/ml_online_model/artifacts/scaler.bin`
- custom training store:
  - `model_store_path: modules/ml_online_model/artifacts/model_custom.bin`
  - `preprocess_store_path: modules/ml_online_model/artifacts/scaler_custom.bin`

## If you change the base class

When updating `MLBaseDetection`, verify these `ml_online_model` responsibilities still match:

- feature preparation in `process_features`
- preprocessor lifecycle (`update_preprocessor`, `transform_features`)
- river learner adaptation (`fit_incremental_model`, `predict_batch`)

## Original model vs custom training details

Default behavior keeps provided artifacts intact.

### 1) Test using original provided model (default)

In `config/slips.yaml`, `ml_online_model` section:

- `mode: test`
- `model_load_path: modules/ml_online_model/artifacts/model.bin`
- `preprocess_load_path: modules/ml_online_model/artifacts/scaler.bin`

### 2) Train a custom model without overwriting original artifacts

In `ml_online_model` section, set:

- `mode: train`
- `train_from_scratch: false` (warm-start from provided model) or `true` (full scratch)
- keep store paths as custom files:
  - `model_store_path: modules/ml_online_model/artifacts/model_custom.bin`
  - `preprocess_store_path: modules/ml_online_model/artifacts/scaler_custom.bin`

Models are persisted at time-window close (or graceful shutdown), not every batch.

### 3) Test using your custom trained model

Switch load paths to your custom files:

- `mode: test`
- `model_load_path: modules/ml_online_model/artifacts/model_custom.bin`
- `preprocess_load_path: modules/ml_online_model/artifacts/scaler_custom.bin`

## Training/testing notes

- `training_batch_size` controls retraining cadence.
- `validate_on_train` controls train/validation metric split during train mode.
- `seed` controls deterministic behavior where applicable.
- `create_performance_metrics_log_files` enables train/test metrics logs.

## How the shipped model was trained

The shipped model was trained using the [SLIPS ML Training Pipeline](https://github.com/stratosphereips/Slips-ML-Training-Pipeline) and selected for best performance on real-world and unseen data. The details of the pipeline are abstracted for simplicity—users do not need to run or understand the pipeline to use this module.

- **Classifier:** `river.tree.SGTClassifier`
- **Preprocessing:** `StandardScaler` and `IncrementalPCA` (from scikit-learn)
- **Training datasets:**
  - Train: `001, 008, 009, 010, 012, 014, 015, 016, 017, 020, 025, 026, 031, 035, 037` (from [security-datasets-for-testing](https://github.com/stratosphereips/security-datasets-for-testing))
  - Test (`test_all`): all datasets above plus `011, 013, 018, 021, 030, 036`
  - Test (`test_unseen`): only datasets not used in training: `018, 020, 021, 025, 026, 030, 031, 035, 036, 037`
- **Performance:**
  - `test_f1: 0.9120`, `test_fpr: 0.0405`
  - `test_unseen_f1: 0.8193`, `test_unseen_fpr: 0.0328`
  - `test_all` = broad evaluation on all test datasets; `test_unseen` = evaluation on datasets not used in training.
- **Retraining:** In SLIPS, retraining is online/incremental using labeled flows and `training_batch_size`.

For more details on the pipeline or datasets, see the [training pipeline repo](https://github.com/stratosphereips/Slips-ML-Training-Pipeline) and [dataset repo](https://github.com/stratosphereips/security-datasets-for-testing).

## Using your own model

You can train your own model externally (using the pipeline or your own code) and use it in this module:

1. Place your model and scaler artifacts in the `modules/ml_online_model/artifacts/` directory (or another path).
2. In `config/slips.yaml`, set:
   - `model_load_path` to your model file
   - `preprocess_load_path` to your scaler file
3. Set `mode: test` to use your custom model for inference.

To train a new model within SLIPS, set `mode: train` and adjust `train_from_scratch` and artifact store paths as described above.

## Visualizing training and testing results

You can visualize model performance using the provided scripts:

- `slips_files/common/ml_modules_utils/plot_train_performance.py` (for training logs)
- `slips_files/common/ml_modules_utils/plot_testing_performance.py` (for testing logs)

Example usage:

```bash
python3 slips_files/common/ml_modules_utils/plot_train_performance.py -f path/to/training.log
python3 slips_files/common/ml_modules_utils/plot_testing_performance.py -f path/to/testing.log
```

## Creating your own ML module

To create a new ML module, see:
- [slips_files/common/abstracts/README.md](../../slips_files/common/abstracts/README.md)
- [docs/create_new_module.md](../../docs/create_new_module.md)

These documents explain the base class, required methods, and configuration for new modules.
