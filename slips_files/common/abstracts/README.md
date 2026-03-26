# ML module base workflow

Shared infrastructure for standalone ML modules (for example `ml_linear_model`, `ml_online_model`) lives in `slips_files/common`.

## Folder purpose

- `ml_module_base.py`: common runtime loop, buffering, config wiring, model I/O, evidence emission.
- `ml_backend_template.py`: copy/adapt this skeleton when creating a new backend.
- `../ml_modules_utils/base_utils.py`: metrics parsing/computation for logs/plots.
- `../ml_modules_utils/plot_train_performance.py`, `../ml_modules_utils/plot_testing_performance.py`: log-based visualization helpers.

## How to add a new model backend

1. Create a new module folder under `modules/` with matching file name (required by Slips discovery), e.g. `modules/ml_xxx/ml_xxx.py`.
2. Quick start: copy `slips_files/common/abstracts/ml_backend_template.py` into your module and adapt.
3. Implement a class inheriting `MLBaseDetection`.
4. Set class metadata: `name`, `description`, `authors`, `module_key`, `module_config_section`.
5. Implement required abstract methods/signatures.

## Required method signatures

- `get_default_artifact_paths(self) -> Tuple[str, str, str, str]`
- `process_features(self, dataset: pd.DataFrame) -> pd.DataFrame`
- `create_empty_model(self) -> Any`
- `create_empty_preprocessor(self) -> Any`
- `update_preprocessor(self, x_train: pd.DataFrame)`
- `transform_features(self, x_data: pd.DataFrame) -> numpy.ndarray`
- `fit_incremental_model(self, x_train: numpy.ndarray, y_train: numpy.ndarray, classes: Optional[list] = None)`
- `predict_batch(self, x_data: numpy.ndarray) -> numpy.ndarray`
- `is_preprocessor_initialized(self) -> bool`
- `train(self, sum_labeled_flows, last_number_of_flows_when_trained)`
- `run_test_on_flow(self, flow: dict)`

## Config contract

Add a section in `config/slips.yaml` matching `module_config_section` with:

- `mode`, `training_batch_size`, `seed`
- `create_performance_metrics_log_files`, `log_suffix`, `test_log_batch_size`
- `model_load_path`, `model_store_path`, `preprocess_load_path`, `preprocess_store_path`

Optional backend-specific keys (for example PCA) should be read in the child class.

## Train/test workflow

Each ML module has its own independent `mode` (`train` or `test`) and artifact paths in `config/slips.yaml`.

- Test provided models: set that module section to `mode: test`.
- Train custom models without overwriting defaults: set `mode: train`, keep `*_store_path` on custom files.
- Test custom models: switch `*_load_path` to custom artifact files and set `mode: test`.
