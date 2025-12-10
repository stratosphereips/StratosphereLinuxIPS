# pipeline_ml_training/config_reader.py
"""
Minimal config reader focused on a single experiment directory.

- YAML-first (PyYAML required)
- Only uses paths.experiment_dir (no separate models/results/logs dirs)
- Resolves experiment_dir_resolved and preprocessing_dir_resolved
- Computes per-command paths under experiment_dir_resolved/commands/
"""

import json
from pathlib import Path

try:
    import yaml
except Exception:
    raise ImportError("PyYAML required. Install with: pip install pyyaml")

YAML_NAMES = ("config.yaml", "config.yml")
JSON_NAMES = ("config.json",)


class ConfigReader(object):
    def __init__(self, path_or_file):
        """
        path_or_file: path to experiment folder or to a config file.
        """
        self.base = Path(path_or_file)
        self.config_path = None
        self._raw = None
        self._resolved = None

    def _find_config(self):
        p = self.base
        if p.is_file():
            return p
        if p.is_dir():
            for name in YAML_NAMES + JSON_NAMES:
                cand = p / name
                if cand.exists():
                    return cand
        return None

    def _read_file(self, path):
        txt = path.read_text(encoding="utf-8")
        sfx = path.suffix.lower()
        if sfx in (".yaml", ".yml"):
            data = yaml.safe_load(txt) or {}
        elif sfx == ".json":
            data = json.loads(txt)
        else:
            try:
                data = yaml.safe_load(txt) or {}
            except Exception:
                data = json.loads(txt)
        if not isinstance(data, dict):
            raise ValueError("Top-level config must be a mapping (dict)")
        return data

    def _defaults(self, raw):
        cfg = dict(raw)

        # basic run settings
        cfg.setdefault("experiment_name", "experiment")
        cfg.setdefault("root", "../../../dataset-private/")
        cfg.setdefault("seed", 1111)
        cfg.setdefault("validation_split", 0.1)
        cfg.setdefault("batch_size_train", 500)
        cfg.setdefault("batch_size_test", 1000)

        # single experiment dir (you control save layout under it)
        paths = cfg.get("paths") or {}
        paths.setdefault("experiment_dir", "./experiments")
        # small helper name for where preprocessing steps are saved under the experiment dir
        paths.setdefault("preprocessing_dir_name", "preprocessing")
        cfg["paths"] = paths

        # dataset-loader defaults
        ds = cfg.get("dataset_loader") or {}
        ds.setdefault("batch_size", cfg["batch_size_train"])
        ds.setdefault("data_subdir", "data")
        ds.setdefault("persist_cache_threshold", 30000)
        ds.setdefault(
            "cache_dir", str((Path(__file__).parent / "cache").resolve())
        )
        ds.setdefault(
            "labeled_filenames",
            ["conn.log.labeled", "labeled-conn.log", "conn.log"],
        )
        ds.setdefault("file_encoding", "utf-8")
        ds.setdefault("file_errors", "ignore")
        ds.setdefault("shuffle_per_epoch", False)
        cfg["dataset_loader"] = ds

        # feature extraction
        feats = cfg.get("features") or {}
        feats.setdefault("default_label", "Benign")
        feats.setdefault(
            "protocols_to_discard",
            ["arp", "ARP", "icmp", "igmp", "ipv6-icmp", ""],
        )
        cfg["features"] = feats

        # preprocessing pipeline
        pc = cfg.get("preprocessing") or {}
        pc.setdefault("steps", [])
        pc.setdefault("save_steps", True)
        pc.setdefault("step_filename_template", "{name}.bin")
        cfg["preprocessing"] = pc

        # model config
        model = cfg.get("model") or {}
        model.setdefault("wrapper", "SKLearnClassifierWrapper")
        model.setdefault("classifier_type", "SGDClassifier")
        model.setdefault(
            "classifier_params", {"loss": "hinge", "penalty": "l2"}
        )
        model.setdefault("save_name", "classifier.bin")
        model.setdefault("classes", [])
        model.setdefault(
            "dummy_flows", {}
        )  # optional override for dummy flows
        cfg["model"] = model

        # commands
        cfg.setdefault("commands", [])
        return cfg

    def _validate(self, cfg):
        if "commands" not in cfg:
            raise ValueError("config must contain 'commands' list")
        if not isinstance(cfg["commands"], list):
            raise ValueError("'commands' must be a list")
        for i, c in enumerate(cfg["commands"]):
            if not isinstance(c, dict):
                raise ValueError("commands[{}] must be a mapping".format(i))
            if "command" not in c:
                raise ValueError(
                    "commands[{}] missing 'command' key".format(i)
                )
            if c["command"] in ("train", "test"):
                if "mixer" not in c:
                    raise ValueError(
                        "commands[{}] missing 'mixer' key (mixer spec required)".format(
                            i
                        )
                    )
                if not isinstance(c["mixer"], dict):
                    raise ValueError(
                        "commands[{}].mixer must be a mapping".format(i)
                    )
                mtype = c["mixer"].get("type")
                if not mtype:
                    raise ValueError(
                        "commands[{}].mixer must include 'type'".format(i)
                    )
                # basic mixer-specific checks
                if mtype == "sequence":
                    if not c["mixer"].get("datasets"):
                        raise ValueError(
                            "sequence mixer requires 'datasets' list"
                        )
                elif mtype == "random_batches":
                    if not c["mixer"].get("datasets"):
                        raise ValueError(
                            "random_batches mixer requires 'datasets' list"
                        )
                    w = c["mixer"].get("weights")
                    if w is not None and len(w) != len(
                        c["mixer"].get("datasets")
                    ):
                        raise ValueError(
                            "random_batches weights length must equal number of datasets"
                        )
                elif mtype == "balanced_by_label":
                    if not c["mixer"].get("datasets"):
                        raise ValueError(
                            "balanced_by_label mixer requires 'datasets' list"
                        )
                else:
                    raise ValueError(
                        "Unknown mixer type '{}' in commands[{}]".format(
                            mtype, i
                        )
                    )
            else:
                pass

    def load(self):
        """
        Load config file, apply defaults, validate, and compute effective values for commands.
        Returns resolved dict.
        """
        if self._resolved is not None:
            return self._resolved
        cfg_path = self._find_config()
        if cfg_path is None:
            raise FileNotFoundError(
                "No config file found under '{}'".format(str(self.base))
            )
        self.config_path = cfg_path
        self._raw = self._read_file(cfg_path)
        self._resolved = self._defaults(self._raw)

        # compute resolved absolute experiment directory
        exp = self._resolved.get("experiment_name")
        base_experiments = Path(self._resolved["paths"]["experiment_dir"])
        self._resolved["paths"]["experiment_dir_resolved"] = str(
            (base_experiments / exp).resolve()
        )

        # preprocessing dir under experiment dir
        self._resolved["paths"]["preprocessing_dir_resolved"] = str(
            (
                Path(self._resolved["paths"]["experiment_dir_resolved"])
                / self._resolved["paths"]["preprocessing_dir_name"]
            ).resolve()
        )

        # dataset cache dir resolved
        ds_cache = Path(self._resolved["dataset_loader"].get("cache_dir"))
        self._resolved["dataset_loader"]["cache_dir_resolved"] = str(
            ds_cache.resolve()
        )

        # compute effective values per command:
        for idx, cmd in enumerate(self._resolved.get("commands", [])):
            # effective validation split precedence: mixer -> command -> global
            cmd_val = cmd.get("validation_split")
            mix_val = None
            if isinstance(cmd.get("mixer"), dict):
                mix_val = cmd["mixer"].get("validation_split")
            if mix_val is not None:
                effective_val = float(mix_val)
            elif cmd_val is not None:
                effective_val = float(cmd_val)
            else:
                effective_val = float(
                    self._resolved.get("validation_split", 0.0)
                )
            cmd["effective_validation_split"] = effective_val

            # effective batch size precedence: command -> global (train/test)
            if "batch_size" in cmd:
                effective_bs = int(cmd["batch_size"])
            else:
                if cmd.get("command") == "test":
                    effective_bs = int(
                        self._resolved.get("batch_size_test", 1000)
                    )
                else:
                    effective_bs = int(
                        self._resolved.get("batch_size_train", 500)
                    )
            cmd["effective_batch_size"] = effective_bs

            # effective paths per-command under the single experiment dir
            safe_name = cmd.get("name") or f"cmd_{idx}"
            exp_base = Path(self._resolved["paths"]["experiment_dir_resolved"])
            cmd_base = exp_base / "commands" / f"{idx}_{safe_name}"
            cmd["paths"] = {
                "command_dir": str(cmd_base.resolve()),
                # convenience: where to save preprocessing and model artifacts for this command
                "preprocessing": str((cmd_base / "preprocessing").resolve()),
                "model": str((cmd_base / "model").resolve()),
                "results": str((cmd_base / "results").resolve()),
                "logs": str((cmd_base / "logs").resolve()),
            }

            # pass effective_validation_split into mixer spec if present
            if isinstance(cmd.get("mixer"), dict):
                cmd["mixer"]["validation_split"] = cmd[
                    "effective_validation_split"
                ]
                if "batch_size" not in cmd["mixer"]:
                    cmd["mixer"]["batch_size"] = cmd["effective_batch_size"]

        # final validation
        self._validate(self._resolved)
        return self._resolved

    def get_feature_extractor_params(self):
        cfg = self.load()
        return {
            "default_label": cfg["features"].get("default_label"),
            "protocols_to_discard": cfg["features"].get(
                "protocols_to_discard"
            ),
        }

    def get_preprocessing_steps(self):
        """
        Returns the raw preprocessing steps spec list.
        Each element is expected like: { name: <str>, type: <str>, params: <dict> }
        Instantiation should be done by the pipeline (mapping type->class).
        """
        cfg = self.load()
        return cfg["preprocessing"].get("steps", [])

    def get_preprocessing_save_options(self):
        cfg = self.load()
        return {
            "save_steps": cfg["preprocessing"].get("save_steps", True),
            "step_filename_template": cfg["preprocessing"].get(
                "step_filename_template", "{name}.bin"
            ),
            "preprocessing_dir": cfg["paths"]["preprocessing_dir_resolved"],
        }

    def get_model_spec(self):
        cfg = self.load()
        return cfg["model"]

    def get_dataset_loader_params(self):
        cfg = self.load()
        return cfg["dataset_loader"]

    def get_paths(self):
        cfg = self.load()
        return cfg["paths"]

    def get_commands(self):
        cfg = self.load()
        return cfg.get("commands", [])

    def save_effective_config(self, target):
        cfg = self.load()
        p = Path(target)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
