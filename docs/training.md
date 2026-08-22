# Training

Slips supports ML retraining with per-module train/test switches. Each ML module has its own section in `config/slips.yaml` and can be trained independently.

Current ML modules:

- `ml_linear_model`
- `ml_online_model`
- `flowmldetection` (legacy module, still available)

## Labels used for training

`ml_linear_model` and `ml_online_model` share the same labeling behavior.
Training uses the flow's `ground_truth_label` when it is present. For Zeek
input, SLIPS maps the Zeek `label` column to this field. Values are
case-insensitive:

- `benign` and `normal` become **Benign**.
- `malicious` and `malware` become **Malicious**.

When a flow has no input label, SLIPS falls back to `parameters.label` in the
active configuration. Its default is `normal`, so every unlabeled flow is
trained as Benign. Other values, including `unknown`, are skipped by training.
The `detailedlabel` field is retained as metadata; it is not the training
target.

## Reproducible training workflow

1. Choose one module and set only that module's `mode: train`.
2. Use one of the input-label approaches below.
3. Set `training_batch_size` to a value no greater than the number of labeled
   flows you expect to process per training batch.
4. Keep the module's custom store paths; they prevent overwriting the shipped
   artifacts.
5. End Slips gracefully or let the time window close so it writes the trained
   artifacts.
6. To evaluate your result, set `mode: test` and change that module's load
   paths to the custom artifacts just written.

### Option A: one mixed, labeled Zeek dataset

Use this when your data has both benign and malicious flows. Add a `label`
column to the relevant Zeek logs and give each flow an accepted value, for
example `normal` or `malicious`. Then set `train_from_scratch: true` for a
new model and run:

```bash
./slips.py -c config/slips.yaml -f dataset/my-labeled-zeek-dir/
```

This is the preferred approach because labels travel with individual flows.
Ensure the dataset includes both classes. The modules add a synthetic sample
only to initialize a classifier missing a class; it does not replace real,
balanced training data.

### Option B: separate known-label PCAP or interface runs

PCAP and interface traffic normally has no per-flow ground-truth label. Before
each run, set `parameters.label` to the known label for the entire input:

```yaml
parameters:
  label: normal  # use malicious for known-malicious input
```

Run your known-benign input, then change the value to `malicious` and run your
known-malicious input. If these are separate runs, continue from the custom
artifacts after the first run:

- `ml_linear_model`: set `model_load_path`, `preprocess_load_path`, and
  `pca_load_path` to its `*_custom.bin` files.
- `ml_online_model`: set `model_load_path` and `preprocess_load_path` to its
  `*_custom.bin` files.
- Set `train_from_scratch: false` before the next run.

Without this handoff, the next run loads the reference artifacts again and does
not continue your previous custom training.

## Important notes

- Train/test is module-specific; there is no global ML train mode.
- `validate_on_train`, `seed`, and metric-log settings are also module-specific.
- Model artifacts are saved at time-window close or graceful shutdown, not after
  every individual flow.


## Finding and plotting module metrics

ML logs are stored inside the selected module's subdirectory of the Slips
output directory. For example, a training run of `ml_linear_model` writes:

```text
output/test7-malicious.pcap_2026-08-22_18:10:46/ml_linear_model/training_ml_linear_model.log
```

`ml_online_model` uses the same layout, with
`ml_online_model/training_ml_online_model.log`. In test mode, replace
`training_` with `testing_`. Plot the exact log for the module and mode you
ran:

```bash
python3 slips_files/common/ml_modules_utils/plot_train_performance.py \
  -f output/test7-malicious.pcap_2026-08-22_18:10:46/ml_linear_model/training_ml_linear_model.log \
  -e test7-linear-training
```

Without `--save_folder`, the generated plots and `summary.txt` are stored in
the same module output directory, under `training/<experiment>/` or
`testing/<experiment>/`. For the command above, they are written to
`output/test7-malicious.pcap_2026-08-22_18:10:46/ml_linear_model/training/test7-linear-training/`,
not to the repository-level `performance_metrics/` directory.

## Official Models and Training Pipeline

The official trained models used by SLIPS ML modules are maintained in a separate repository:

- [Stratosphere-ML-trained-models](https://github.com/stratosphereips/Stratosphere-ML-trained-models): Official, versioned, and evaluated ML models for SLIPS modules (including ml_linear_model and ml_online_model).

The experiment/training pipeline is maintained as a standalone repository:

- [Slips-ML-Training-Pipeline](https://github.com/stratosphereips/pipeline_ml_training_for_SLIPS): Used to produce and evaluate shipped ML artifacts for SLIPS modules.

See also: `docs/related_repos.md`
