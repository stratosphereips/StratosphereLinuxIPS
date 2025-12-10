# tests/test_config_reader.py
import json
from pathlib import Path
import pytest
import yaml

from pipeline_ml_training.conf_reader import ConfigReader


# Helper to write YAML
def write_yaml(path, data):
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


class TestConfigReader:
    def test_user_overrides_defaults_and_effective_values(self, tmp_path):
        """
        Single test that verifies many fields are overridden by the user config,
        that lists (preprocessing.steps, commands) are replaced (not merged),
        and that per-command effective fields (batch size, validation split)
        and per-command paths are computed.
        """
        # create defaults file
        defaults = {
            "experiment_name": "default_exp",
            "root": "/data/default_root",
            "batch_size_train": 500,
            "paths": {"experiment_dir": "./experiments"},
            "dataset_loader": {"cache_dir": "/tmp/default_cache"},
            "preprocessing": {
                "steps": [
                    {"name": "scaler", "type": "StandardScaler", "params": {}}
                ]
            },
            "model": {
                "classifier_params": {"alpha": 1.0},
                "save_name": "classifier.bin",
            },
            "commands": [
                {
                    "name": "default_cmd",
                    "command": "train",
                    "mixer": {"type": "sequence", "datasets": ["001"]},
                }
            ],
        }
        defaults_path = tmp_path / "default_config.yaml"
        write_yaml(defaults_path, defaults)

        # create user config that overrides several fields
        user_cfg = {
            "experiment_name": "my_exp",
            "batch_size_train": 400,
            "paths": {"experiment_dir": "./my_exps"},
            "preprocessing": {
                # this should replace the default list entirely
                "steps": [
                    {
                        "name": "my_scaler",
                        "type": "StandardScaler",
                        "params": {},
                    }
                ]
            },
            "model": {"classifier_params": {"alpha": 0.5}},
            "commands": [
                {
                    "name": "user_cmd",
                    "command": "train",
                    "mixer": {"type": "sequence", "datasets": ["008"]},
                }
            ],
        }
        # put user config in an experiment folder
        exp_dir = tmp_path / "exp_folder"
        exp_dir.mkdir()
        user_cfg_path = exp_dir / "config.yaml"
        write_yaml(user_cfg_path, user_cfg)

        # instantiate reader with explicit defaults_path
        cr = ConfigReader(str(exp_dir), defaults_path=str(defaults_path))
        resolved = cr.load()

        # top-level overrides
        assert resolved["experiment_name"] == "my_exp"
        assert int(resolved["batch_size_train"]) == 400

        # default not overridden remains present
        assert resolved["dataset_loader"]["cache_dir"] == "/tmp/default_cache"

        # preprocessing.steps replaced by user list (not merged)
        steps = resolved["preprocessing"]["steps"]
        assert isinstance(steps, list)
        assert len(steps) == 1
        assert steps[0]["name"] == "my_scaler"

        # model.classifier_params overridden
        assert resolved["model"]["classifier_params"]["alpha"] == 0.5

        # commands replaced by user commands
        cmds = resolved["commands"]
        assert len(cmds) == 1
        assert cmds[0]["name"] == "user_cmd"
        assert cmds[0]["mixer"]["datasets"] == ["008"]

        # effective per-command values: batch size should equal batch_size_train (400)
        assert cmds[0]["effective_batch_size"] == 400

        # per-command paths exist and resolve under the experiment dir/resolved name
        paths = resolved["paths"]
        assert "experiment_dir_resolved" in paths
        exp_resolved = Path(paths["experiment_dir_resolved"]).resolve()
        expected_cmd_dir = (exp_resolved / "commands" / "0_user_cmd").resolve()
        assert (
            Path(cmds[0]["paths"]["command_dir"]).resolve() == expected_cmd_dir
        )

        # effective_validation_split present (defaults to global validation_split)
        assert "effective_validation_split" in cmds[0]

        # convenience accessor functions
        assert cr.get_feature_extractor_params()["default_label"] == resolved[
            "features"
        ].get("default_label", "Benign")
        assert cr.get_model_spec() == resolved["model"]

        # save effective config (no exception)
        out_file = tmp_path / "effective.json"
        cr.save_effective_config(str(out_file))
        assert out_file.exists()
        loaded = json.loads(out_file.read_text(encoding="utf-8"))
        assert loaded["experiment_name"] == "my_exp"

    def test_load_new_mutual_exclusive_validation_and_missing_defaults(
        self, tmp_path
    ):
        """
        Validate the reader raises if both 'load' and 'new' are present in the same command.
        Also assert that if an explicit defaults_path is provided and does not exist,
        load() raises FileNotFoundError.
        """
        # create a minimal user config with both load and new in a command
        user_cfg = {
            "experiment_name": "bad_exp",
            "commands": [
                {
                    "name": "bad_cmd",
                    "command": "train",
                    "mixer": {"type": "sequence", "datasets": ["001"]},
                    "load": {"model": "/some/path"},
                    "new": {"model": {"classifier_type": "SGDClassifier"}},
                }
            ],
        }
        exp_dir = tmp_path / "bad_exp"
        exp_dir.mkdir()
        user_cfg_path = exp_dir / "config.yaml"
        write_yaml(user_cfg_path, user_cfg)

        # Using packaged defaults (none) is fine; the validation runs on merged config and should raise
        cr = ConfigReader(str(exp_dir))
        with pytest.raises(ValueError):
            cr.load()

        # If defaults_path is explicitly given but missing, load() should raise FileNotFoundError
        missing_defaults = tmp_path / "no_such_defaults.yaml"
        cr2 = ConfigReader(str(exp_dir), defaults_path=str(missing_defaults))
        with pytest.raises(FileNotFoundError):
            cr2.load()
