# Training

Slips supports ML retraining with per-module train/test switches. Each ML module has its own section in `config/slips.yaml` and can be trained independently.

Current ML modules:

- `ml_linear_model`
- `ml_online_model`
- `flowmldetection` (legacy module, still available)

## Per-module workflow

1. Select only the module you want to train and set its section to `mode: train`.
2. Set `parameters.label` (`normal` or `malicious`) for the input you are feeding.
3. Run Slips with your training data (pcap, Zeek directory, or interface).
4. Repeat with additional labeled traffic as needed.
5. Switch the same module back to `mode: test` to use trained artifacts.

Example run commands:

```bash
./slips.py -c config/slips.yaml -f ~/my-traffic.pcap
./slips.py -c config/slips.yaml -f ~/my-zeek-dir/
./slips.py -c config/slips.yaml -i eth0
```

## Important notes

- Train/test is module-specific; there is no global ML train mode.
- Keep model load/store paths per module (`ml_linear_model` and `ml_online_model` sections) so custom training does not overwrite shipped artifacts.
- `training_batch_size`, `validate_on_train`, `seed`, and log settings are also module-specific.


## Official Models and Training Pipeline

The official trained models used by SLIPS ML modules are maintained in a separate repository:

- [Stratosphere-ML-trained-models](https://github.com/stratosphereips/Stratosphere-ML-trained-models): Official, versioned, and evaluated ML models for SLIPS modules (including ml_linear_model and ml_online_model).

The experiment/training pipeline is maintained as a standalone repository:

- [Slips-ML-Training-Pipeline](https://github.com/stratosphereips/pipeline_ml_training_for_SLIPS): Used to produce and evaluate shipped ML artifacts for SLIPS modules.

See also: `docs/related_repos.md`
