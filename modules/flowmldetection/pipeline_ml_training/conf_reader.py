# pipeline_ml_training/config_reader.py
"""
ConfigReader that first loads defaults from a YAML, then user config and merges.

Usage:
    cr = ConfigReader(path_or_file)                 # uses packaged default_config.yaml if present
    cr = ConfigReader(path_or_file, defaults_path="path/to/my_defaults.yml")

After load(): use helper accessors like get_commands(), get_model_spec(), get_paths(), etc.
"""

import json
from pathlib import Path

try:
    import yaml
except Exception:
    raise ImportError("PyYAML required. Install with: pip install pyyaml")

YAML_NAMES = ("config.yaml", "config.yml")
JSON_NAMES = ("config.json",)


def _load_yaml_file(path):
    txt = Path(path).read_text(encoding="utf-8")
    sfx = Path(path).suffix.lower()
    if sfx in (".yaml", ".yml"):
        data = yaml.safe_load(txt) or {}
    elif sfx == ".json":
        import json as _json

        data = _json.loads(txt)
    else:
        # prefer YAML parsing, fall back to JSON
        try:
            data = yaml.safe_load(txt) or {}
        except Exception:
            import json as _json

            data = _json.loads(txt)
    if not isinstance(data, dict):
        raise ValueError(
            f"Top-level config in {path} must be a mapping (dict)"
        )
    return data


def _deep_merge(default, override):
    """
    Recursively merge override into default and return result.
    - dicts: merge keys recursively
    - lists: override replaces default list
    - scalars: override replaces default scalar
    """
    if default is None:
        return override
    if override is None:
        return default

    if isinstance(default, dict) and isinstance(override, dict):
        out = dict(default)
        for k, v in override.items():
            if k in default:
                out[k] = _deep_merge(default[k], v)
            else:
                out[k] = v
        return out
    # for lists and all other types, the override replaces default
    return override


class ConfigReader(object):
    def __init__(self, path_or_file, defaults_path=None):
        """
        path_or_file: path to experiment folder or to a config file.
        defaults_path: optional path to defaults YAML. If None, looks for
                       'default_config.yaml' next to this module.
        """
        self.base = Path(path_or_file)
        self.defaults_path = (
            Path(defaults_path) if defaults_path is not None else None
        )
        self.config_path = None
        self._raw_user = None
        self._raw_defaults = None
        self._resolved = None

    def _find_user_config(self):
        p = self.base
        if p.is_file():
            return p
        if p.is_dir():
            for name in YAML_NAMES + JSON_NAMES:
                cand = p / name
                if cand.exists():
                    return cand
        return None

    def _find_default_config(self):
        # explicit path wins
        if self.defaults_path is not None:
            if self.defaults_path.exists():
                return self.defaults_path
            raise FileNotFoundError(
                f"Defaults file {str(self.defaults_path)} not found"
            )
        # fallback to packaged default_config.yaml next to this file
        pack = Path(__file__).parent / "default_config.yaml"
        if pack.exists():
            return pack
        return None

    def _defaults_fallback(self, raw):
        """
        Ensure minimal defaults (in case defaults file is missing).
        This mirrors the minimal defaults we want always present.
        """
        cfg = dict(raw) if raw is not None else {}
        cfg.setdefault("experiment_name", "experiment")
        cfg.setdefault("root", "../../../dataset-private/")
        cfg.setdefault("seed", 1111)
        cfg.setdefault("validation_split", 0.1)
        cfg.setdefault("batch_size_train", 500)
        cfg.setdefault("batch_size_test", 1000)
        paths = cfg.get("paths") or {}
        paths.setdefault("experiment_dir", "./experiments")
        paths.setdefault("preprocessing_dir_name", "preprocessing")
        cfg["paths"] = paths

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

        feats = cfg.get("features") or {}
        feats.setdefault("default_label", "Benign")
        feats.setdefault(
            "protocols_to_discard",
            ["arp", "ARP", "icmp", "igmp", "ipv6-icmp", ""],
        )
        cfg["features"] = feats

        pc = cfg.get("preprocessing") or {}
        pc.setdefault("steps", [])
        pc.setdefault("save_steps", True)
        pc.setdefault("step_filename_template", "{name}.bin")
        cfg["preprocessing"] = pc

        model = cfg.get("model") or {}
        model.setdefault("wrapper", "SKLearnClassifierWrapper")
        model.setdefault("classifier_type", "SGDClassifier")
        model.setdefault(
            "classifier_params", {"loss": "hinge", "penalty": "l2"}
        )
        model.setdefault("save_name", "classifier.bin")
        model.setdefault("classes", [])
        model.setdefault("dummy_flows", {})
        cfg["model"] = model

        cfg.setdefault("commands", [])
        return cfg

    def _validate(self, cfg):
        # basic checks: commands is list
        if "commands" not in cfg or not isinstance(cfg["commands"], list):
            raise ValueError("config must include 'commands' as a list")
        for i, cmd in enumerate(cfg["commands"]):
            if not isinstance(cmd, dict):
                raise ValueError(f"commands[{i}] must be a mapping")
            if "command" not in cmd:
                raise ValueError(f"commands[{i}] missing 'command' key")
            if cmd.get("command") in ("train", "test"):
                mixer = cmd.get("mixer")
                if not isinstance(mixer, dict):
                    raise ValueError(
                        f"commands[{i}]: 'mixer' mapping is required for train/test"
                    )
                mtype = mixer.get("type")
                if mtype not in (
                    "sequence",
                    "random_batches",
                    "balanced_by_label",
                ):
                    raise ValueError(
                        f"commands[{i}]: unknown mixer.type '{mtype}'"
                    )
                if mtype == "sequence":
                    if not mixer.get("datasets"):
                        raise ValueError(
                            f"commands[{i}]: sequence mixer requires 'datasets' list"
                        )
                if mtype == "random_batches":
                    if not mixer.get("datasets"):
                        raise ValueError(
                            f"commands[{i}]: random_batches mixer requires 'datasets' list"
                        )
                    w = mixer.get("weights")
                    if w is not None and len(w) != len(
                        mixer.get("datasets", [])
                    ):
                        raise ValueError(
                            f"commands[{i}]: random_batches weights length mismatch"
                        )
                if mtype == "balanced_by_label":
                    if not mixer.get("datasets"):
                        raise ValueError(
                            f"commands[{i}]: balanced_by_label mixer requires 'datasets' list"
                        )

            # load/new mutually exclusive
            load_spec = cmd.get("load")
            new_spec = cmd.get("new")
            if load_spec is not None and new_spec is not None:
                raise ValueError(
                    f"commands[{i}] contains both 'load' and 'new' (mutually exclusive)"
                )

            if load_spec is not None:
                if not isinstance(load_spec, dict):
                    raise ValueError(f"commands[{i}].load must be a mapping")
                if "preprocessing" in load_spec and not isinstance(
                    load_spec.get("preprocessing"), str
                ):
                    raise ValueError(
                        f"commands[{i}].load.preprocessing must be a string path"
                    )
                if "model" in load_spec and not isinstance(
                    load_spec.get("model"), str
                ):
                    raise ValueError(
                        f"commands[{i}].load.model must be a string path"
                    )
                if "model_filename" in load_spec and not isinstance(
                    load_spec.get("model_filename"), str
                ):
                    raise ValueError(
                        f"commands[{i}].load.model_filename must be a string"
                    )
                if "strict" in load_spec and not isinstance(
                    load_spec.get("strict"), bool
                ):
                    raise ValueError(
                        f"commands[{i}].load.strict must be a boolean"
                    )

            if new_spec is not None:
                if not isinstance(new_spec, dict):
                    raise ValueError(f"commands[{i}].new must be a mapping")
                allowed = ("model", "preprocessing_steps")
                for k in new_spec.keys():
                    if k not in allowed:
                        raise ValueError(
                            f"commands[{i}].new unknown key '{k}'"
                        )
                if "model" in new_spec and not isinstance(
                    new_spec.get("model"), dict
                ):
                    raise ValueError(
                        f"commands[{i}].new.model must be a mapping"
                    )
                if "preprocessing_steps" in new_spec and not isinstance(
                    new_spec.get("preprocessing_steps"), list
                ):
                    raise ValueError(
                        f"commands[{i}].new.preprocessing_steps must be a list"
                    )

    def load(self):
        """
        Load defaults (if available), then user config, deep-merge (user overrides defaults),
        apply minimal fallbacks, compute resolved paths and effective per-command values,
        then validate and return the resolved config dict.
        """
        if self._resolved is not None:
            return self._resolved

        # load defaults if available
        dpath = self._find_default_config()
        if dpath is not None:
            self._raw_defaults = _load_yaml_file(dpath)
        else:
            self._raw_defaults = {}

        # load user config
        cfg_path = self._find_user_config()
        if cfg_path is None:
            raise FileNotFoundError(
                f"No config file found under '{str(self.base)}'"
            )
        self.config_path = cfg_path
        self._raw_user = _load_yaml_file(cfg_path)

        # deep merge: defaults <- user (user overrides)
        merged = _deep_merge(self._raw_defaults, self._raw_user)

        # enforce minimal keys / fallback defaults
        merged = self._defaults_fallback(merged)

        # compute experiment_dir_resolved and preprocessing_dir_resolved
        exp = merged.get("experiment_name")
        base_experiments = Path(merged["paths"]["experiment_dir"])
        merged["paths"]["experiment_dir_resolved"] = str(
            (base_experiments / exp).resolve()
        )
        merged["paths"]["preprocessing_dir_resolved"] = str(
            (
                Path(merged["paths"]["experiment_dir_resolved"])
                / merged["paths"]["preprocessing_dir_name"]
            ).resolve()
        )

        # dataset cache dir resolved
        ds_cache = Path(merged["dataset_loader"].get("cache_dir"))
        merged["dataset_loader"]["cache_dir_resolved"] = str(
            ds_cache.resolve()
        )

        # compute per-command effective values and paths
        commands = merged.get("commands", [])
        for idx, cmd in enumerate(commands):
            # effective validation split: mixer -> command -> global
            cmd_val = cmd.get("validation_split")
            mix_val = None
            if isinstance(cmd.get("mixer"), dict):
                mix_val = cmd["mixer"].get("validation_split")
            if mix_val is not None:
                effective_val = float(mix_val)
            elif cmd_val is not None:
                effective_val = float(cmd_val)
            else:
                effective_val = float(merged.get("validation_split", 0.0))
            cmd["effective_validation_split"] = effective_val

            # effective batch size
            if "batch_size" in cmd:
                effective_bs = int(cmd["batch_size"])
            else:
                if cmd.get("command") == "test":
                    effective_bs = int(merged.get("batch_size_test", 1000))
                else:
                    effective_bs = int(merged.get("batch_size_train", 500))
            cmd["effective_batch_size"] = effective_bs

            # per-command paths under experiment_dir
            safe_name = cmd.get("name") or f"cmd_{idx}"
            exp_base = Path(merged["paths"]["experiment_dir_resolved"])
            cmd_base = exp_base / "commands" / f"{idx}_{safe_name}"
            cmd["paths"] = {
                "command_dir": str(cmd_base.resolve()),
                "preprocessing": str((cmd_base / "preprocessing").resolve()),
                "model": str((cmd_base / "model").resolve()),
                "results": str((cmd_base / "results").resolve()),
                "logs": str((cmd_base / "logs").resolve()),
            }

            # write effective values into mixer mapping if present
            if isinstance(cmd.get("mixer"), dict):
                cmd["mixer"]["validation_split"] = cmd[
                    "effective_validation_split"
                ]
                if "batch_size" not in cmd["mixer"]:
                    cmd["mixer"]["batch_size"] = cmd["effective_batch_size"]

        # run validation
        self._validate(merged)

        self._resolved = merged
        return self._resolved

    # ----------------------- helper accessors -----------------------
    def get_feature_extractor_params(self):
        cfg = self.load()
        return {
            "default_label": cfg["features"].get("default_label"),
            "protocols_to_discard": cfg["features"].get(
                "protocols_to_discard"
            ),
        }

    def get_preprocessing_steps(self):
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
        return cfg.get("model", {})

    def get_dataset_loader_params(self):
        cfg = self.load()
        return cfg.get("dataset_loader", {})

    def get_paths(self):
        cfg = self.load()
        return cfg.get("paths", {})

    def get_commands(self):
        cfg = self.load()
        return cfg.get("commands", [])

    def get_command_load_spec(self, cmd_or_idx):
        cfg = self.load()
        if isinstance(cmd_or_idx, int):
            cmds = cfg.get("commands", [])
            if cmd_or_idx < 0 or cmd_or_idx >= len(cmds):
                return None
            return cmds[cmd_or_idx].get("load")
        elif isinstance(cmd_or_idx, dict):
            return cmd_or_idx.get("load")
        return None

    def get_command_new_spec(self, cmd_or_idx):
        cfg = self.load()
        if isinstance(cmd_or_idx, int):
            cmds = cfg.get("commands", [])
            if cmd_or_idx < 0 or cmd_or_idx >= len(cmds):
                return None
            return cmds[cmd_or_idx].get("new")
        elif isinstance(cmd_or_idx, dict):
            return cmd_or_idx.get("new")
        return None

    def save_effective_config(self, target):
        cfg = self.load()
        p = Path(target)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
