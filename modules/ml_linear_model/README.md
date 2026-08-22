# `ml_linear_model` (user guide)

This module provides a ready-to-use sklearn flow model for SLIPS.

## What users need

The runtime files are:

- `modules/ml_linear_model/artifacts/model.bin`
- `modules/ml_linear_model/artifacts/scaler.bin`
- `modules/ml_linear_model/artifacts/pca.bin`

Inference/training pipeline in the module:

1. scale features with `scaler.bin`
2. apply `IncrementalPCA` from scikit-learn (`pca.bin`)
3. classify with `model.bin`

PCA is mandatory for this model family (not optional): runtime always uses scaler -> PCA -> model in this order.


## How the shipped model was trained

The shipped model was trained using the [SLIPS ML Training Pipeline](https://github.com/stratosphereips/Slips-ML-Training-Pipeline) and selected for best performance on real-world and unseen data. The details of the pipeline are abstracted for simplicity—users do not need to run or understand the pipeline to use this module.

- **Classifier:** scikit-learn linear model (see pipeline repo for details)
- **Preprocessing:** `StandardScaler` and `IncrementalPCA` (from scikit-learn)
- **Training datasets:**
  - Train: `001, 008, 009, 010, 012, 014, 015, 016, 017, 020, 025, 026, 031, 035, 037` (from [security-datasets-for-testing](https://github.com/stratosphereips/security-datasets-for-testing))
  - Test (`test_all`): all datasets above plus `011, 012, 013, 014, 015, 016, 017, 018, 020, 021, 025, 026, 030, 031, 035, 036, 037`
  - Test (`test_unseen`): only datasets not used in training: `018, 020, 021, 025, 026, 030, 031, 035, 036, 037`
- **Performance:**
  - `test_all`: `F1 = 0.9362`, `FPR = 0.3545`
  - `test_unseen`: `F1 = 0.9308`, `FPR = 0.1063`
  - `test_all` = broad evaluation on all test datasets; `test_unseen` = evaluation on datasets not used in training.
- **Retraining:** In SLIPS, retraining is online/incremental using labeled flows and `training_batch_size`.

For more details on the pipeline or datasets, see the [training pipeline repo](https://github.com/stratosphereips/Slips-ML-Training-Pipeline) and [dataset repo](https://github.com/stratosphereips/security-datasets-for-testing).


## Labels and training with your data

Both standalone ML modules use the same label rules. A flow is trained with its
`ground_truth_label` when the input provides one. For Zeek input, SLIPS maps a
Zeek `label` field to `ground_truth_label`. Accepted values are case-insensitive:

- `benign` or `normal` means **Benign**.
- `malicious` or `malware` means **Malicious**.

If a flow has no `ground_truth_label`, SLIPS uses `parameters.label` from the
active configuration. The default is `normal`, so unlabeled traffic trains as
Benign. Labels other than Benign or Malicious are not added to a training batch.

### Reproducible training

For a mixed, labeled Zeek dataset, add a `label` column to the relevant Zeek
logs, with one of the accepted values for every training flow. Then set this
module's `mode: train`, optionally set `train_from_scratch: true`, choose a
`training_batch_size` no larger than the labeled data you will supply, and run:

```bash
./slips.py -c config/slips.yaml -f dataset/my-labeled-zeek-dir/
```

For an unlabeled PCAP or interface, use separate runs and explicitly set
`parameters.label` for each run. For example, run known-benign traffic with
`parameters.label: normal`; then run known-malicious traffic with
`parameters.label: malicious`. After the first run, set `train_from_scratch:
false` and point the load paths to the custom artifacts produced by that run
before starting the next run. Otherwise the next run reloads the shipped model
instead of continuing your custom training.

`ml_linear_model` needs all three custom artifacts for continuation:
`model_custom.bin`, `scaler_custom.bin`, and `pca_custom.bin`. On graceful
shutdown or time-window close, training writes them to the configured store
paths. To evaluate the resulting model, switch to `mode: test` and use those
same custom paths as its load paths.

## Using your own model

After you trained your own model, you can use it like this:

1. Set `mode: test` to use your custom model for testing (normal inference)
2. Place your model, scaler, and PCA artifacts in the `modules/ml_linear_model/artifacts/` directory (or another path).
3. In `config/slips.yaml`, set:
   - `model_load_path` to your model file
   - `preprocess_load_path` to your scaler file
   - `pca_load_path` to your PCA file
4. Run slips

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
- [docs/create_new_module.md#ml-module](../../docs/create_new_module.md#ml-module)
- [docs/create_new_module.md](../../docs/create_new_module.md)

These documents explain the base class, required methods, and configuration for new modules.

## How to use in SLIPS

`config/slips.yaml` is already wired for this module via the `ml_linear_model` section:

- `model_load_path`
- `preprocess_load_path`
- `pca_load_path`

PCA is implemented directly in the backend code path for `ml_linear_model`.

For reproducibility, keep `seed` fixed in `config/slips.yaml`.

## Train/test (module-specific)

Canonical workflow is in `docs/create_new_module.md#ml-module`.

`ml_linear_model`-specific paths:

- original test load:
  - `model_load_path: modules/ml_linear_model/artifacts/model.bin`
  - `preprocess_load_path: modules/ml_linear_model/artifacts/scaler.bin`
  - `pca_load_path: modules/ml_linear_model/artifacts/pca.bin`
- custom training store:
  - `model_store_path: modules/ml_linear_model/artifacts/model_custom.bin`
  - `preprocess_store_path: modules/ml_linear_model/artifacts/scaler_custom.bin`
  - `pca_store_path: modules/ml_linear_model/artifacts/pca_custom.bin`

## If you change the base class

When updating `MLBaseDetection`, verify these `ml_linear_model` responsibilities still match:

- feature preparation in `process_features`
- preprocessor lifecycle (`update_preprocessor`, `transform_features`)
- model lifecycle (`fit_incremental_model`, `predict_batch`)
- PCA load/store fields (`pca_load_path`, `pca_store_path`) in `init/read_model/store_model`

## Original model vs custom training details

Default behavior keeps provided artifacts intact.

### 1) Test using original provided model (default)

In `ml_linear_model` section, keep:

- `mode: test`
- `model_load_path: modules/ml_linear_model/artifacts/model.bin`
- `preprocess_load_path: modules/ml_linear_model/artifacts/scaler.bin`
- `pca_load_path: modules/ml_linear_model/artifacts/pca.bin`

### 2) Train a custom model without overwriting original artifacts

In `ml_linear_model` section, set:

- `mode: train`
- `train_from_scratch: false` (warm-start from provided model) or `true` (full scratch)
- keep store paths as custom files:
  - `model_store_path: modules/ml_linear_model/artifacts/model_custom.bin`
  - `preprocess_store_path: modules/ml_linear_model/artifacts/scaler_custom.bin`
  - `pca_store_path: modules/ml_linear_model/artifacts/pca_custom.bin`

Models are persisted at time-window close (or graceful shutdown), not every batch.

### 3) Test using your custom trained model

Switch load paths to your custom files:

- `mode: test`
- `model_load_path: modules/ml_linear_model/artifacts/model_custom.bin`
- `preprocess_load_path: modules/ml_linear_model/artifacts/scaler_custom.bin`
- `pca_load_path: modules/ml_linear_model/artifacts/pca_custom.bin`
