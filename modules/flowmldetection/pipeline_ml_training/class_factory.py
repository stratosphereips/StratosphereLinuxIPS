# pipeline_ml_training/factory.py
"""
Combined factories for transformers, classifiers, wrappers, feature extractor and dataset loaders.

This version uses a generic module-search approach:
 - tries to find a class by name across a list of likely modules
 - falls back to dotted-path import when provided
 - special handling for River ensemble "model" nested spec
"""

import importlib


# Helper: import class from dotted path
def _import_from_path(path):
    comps = path.split(".")
    if len(comps) < 2:
        raise ImportError("Dotted path expected, got: {}".format(path))
    module_name = ".".join(comps[:-1])
    cls_name = comps[-1]
    mod = importlib.import_module(module_name)
    return getattr(mod, cls_name)


# Generic finder: search a list of module names for a class named 'cls_name'
def _find_class_in_modules(cls_name, module_names):
    # try exact, then try with first-char uppercase
    candidates = [
        cls_name,
        cls_name[0].upper() + cls_name[1:] if cls_name else cls_name,
    ]
    for mod_name in module_names:
        try:
            mod = importlib.import_module(mod_name)
        except Exception:
            continue
        for cand in candidates:
            if hasattr(mod, cand):
                return getattr(mod, cand)
    return None


# -------------------------
# TRANSFORMER FACTORY
# -------------------------
def build_transformer(step_spec):
    """
    step_spec: { "name": "...", "type": "StandardScaler" or "sklearn.preprocessing.StandardScaler", "params": {...} }
    Generic strategy:
      1) If dotted path -> import and instantiate
      2) Try searching common sklearn modules for the class name
      3) Raise helpful error
    """
    if not isinstance(step_spec, dict):
        raise ValueError("step_spec must be a dict")
    t = step_spec.get("type")
    params = step_spec.get("params", {}) or {}
    if not t:
        raise ValueError("step 'type' missing in transformer spec")

    # dotted path quick path
    if "." in t:
        try:
            Cls = _import_from_path(t)
            return Cls(**params)
        except Exception as e:
            raise RuntimeError(
                "Failed to import transformer via dotted path '{}': {}".format(
                    t, e
                )
            )

    # module search list for transformers (common sklearn locations)
    transformer_modules = [
        "sklearn.preprocessing",
        "sklearn.impute",
        "sklearn.decomposition",
        "sklearn.feature_extraction",
        "sklearn.pipeline",
        "sklearn.compose",
        "sklearn.preprocessing._encoders",  # sometimes encoders live here
    ]

    # try to find the class
    Cls = _find_class_in_modules(t, transformer_modules)
    if Cls is not None:
        try:
            return Cls(**params)
        except Exception as e:
            raise RuntimeError(
                "Found transformer '{}' but instantiation failed: {}".format(
                    t, e
                )
            )

    raise ValueError(
        "Unknown transformer type '{}'. Tried sklearn modules and dotted import.".format(
            t
        )
    )


# -------------------------
# CLASSIFIER FACTORY
# -------------------------
def _instantiate_river_nested_model_if_needed(params):
    """
    If params contains a nested 'model' dict (spec), try to build the inner model
    by searching common river modules and replace params['model'] with instantiated object.
    This mutates params (makes a shallow copy in caller if needed).
    """
    if not isinstance(params, dict):
        return params
    nested = params.get("model")
    if not isinstance(nested, dict):
        return params
    inner_type = nested.get("type")
    inner_params = nested.get("params", {}) or {}
    if not inner_type:
        raise ValueError("Nested 'model' spec is missing 'type' key")

    # search locations for river models
    river_submodules = [
        "river.tree",
        "river.ensemble",
        "river.linear_model",
        "river.naive_bayes",
        "river.neighbors",
        "river.bayes",
        "river.cluster",
        "river.utils",
    ]
    Cls = _find_class_in_modules(inner_type, river_submodules)
    if Cls is None:
        # try dotted import as fallback
        if "." in inner_type:
            Cls = _import_from_path(inner_type)
    if Cls is None:
        raise RuntimeError(
            "Could not find River inner model class '{}' in known river submodules".format(
                inner_type
            )
        )
    try:
        params["model"] = Cls(**inner_params)
    except Exception as e:
        raise RuntimeError(
            "Failed to instantiate River inner model '{}' : {}".format(
                inner_type, e
            )
        )
    return params


def build_classifier(model_spec):
    """
    Generic classifier builder.
    model_spec: { "classifier_type": "SGDClassifier" or "river.tree.HoeffdingTreeClassifier", "classifier_params": {...} }
    Strategy:
      - if dotted path: import and instantiate
      - try sklearn modules
      - try river modules (with special nested-model handling)
      - try xgboost if requested
    """
    if not isinstance(model_spec, dict):
        raise ValueError("model_spec must be a dict")
    t = model_spec.get("classifier_type") or model_spec.get("type")
    params = dict(
        model_spec.get("classifier_params", {}) or {}
    )  # copy to allow mutation
    if not t:
        raise ValueError("classifier_type missing in model_spec")

    # dotted path quick path
    if "." in t:
        try:
            Cls = _import_from_path(t)
            # if this is a river class and has nested model, handle it
            if (
                t.startswith("river.")
                and isinstance(params, dict)
                and "model" in params
                and isinstance(params["model"], dict)
            ):
                params = _instantiate_river_nested_model_if_needed(params)
            return Cls(**params)
        except Exception as e:
            raise RuntimeError(
                "Failed to import classifier via dotted path '{}': {}".format(
                    t, e
                )
            )

    # try sklearn modules generically
    sklearn_modules = [
        "sklearn.linear_model",
        "sklearn.ensemble",
        "sklearn.svm",
        "sklearn.naive_bayes",
        "sklearn.tree",
        "sklearn.neighbors",
    ]
    Cls = _find_class_in_modules(t, sklearn_modules)
    if Cls is not None:
        try:
            return Cls(**params)
        except Exception as e:
            raise RuntimeError(
                "Found sklearn classifier '{}' but instantiation failed: {}".format(
                    t, e
                )
            )

    # try river modules generically
    # handle nested model param if needed (ensembles)
    river_modules = [
        "river.tree",
        "river.ensemble",
        "river.linear_model",
        "river.naive_bayes",
        "river.neighbors",
        "river.ensemble.bagging",
    ]
    Cls = _find_class_in_modules(t, river_modules)
    if Cls is not None:
        try:
            # If nested model spec exists, instantiate inner model first
            if (
                isinstance(params, dict)
                and "model" in params
                and isinstance(params["model"], dict)
            ):
                params = _instantiate_river_nested_model_if_needed(params)
            return Cls(**params)
        except Exception as e:
            raise RuntimeError(
                "Found river classifier '{}' but instantiation failed: {}".format(
                    t, e
                )
            )

    # try xgboost as a last resort
    try:
        xgb = importlib.import_module("xgboost")
        if hasattr(xgb, "XGBClassifier") and t.lower() in (
            "xgbclassifier",
            "xgboost",
            "xgboostclassifier",
            "xgb",
        ):
            from xgboost import XGBClassifier

            return XGBClassifier(**params)
    except Exception:
        pass

    # final fallback: can't find class
    raise ValueError(
        "Unknown classifier type '{}'. Tried sklearn, river and dotted import.".format(
            t
        )
    )


# -------------------------
# WRAPPER FACTORY
# -------------------------
def build_wrapper(
    wrapper_name, classifier_obj, preprocessing_handler=None, model_spec=None
):
    model_spec = model_spec or {}
    w = wrapper_name or model_spec.get("wrapper") or "SKLearnClassifierWrapper"
    try:
        wn = w.lower()
    except Exception:
        wn = str(w).lower()

    def _instantiate_with_fallback(
        Cls, classifier_obj, preprocessing_handler, model_spec
    ):
        try:
            return Cls(
                classifier_obj,
                preprocessing_handler=preprocessing_handler,
                classes=model_spec.get("classes", []),
                dummy_flows=model_spec.get("dummy_flows", {}),
            )
        except TypeError:
            pass
        try:
            return Cls(
                classifier_obj, preprocessing_handler=preprocessing_handler
            )
        except TypeError:
            pass
        try:
            return Cls(classifier_obj)
        except Exception as e:
            raise RuntimeError(
                "Failed to instantiate wrapper class {}: {}".format(Cls, e)
            )

    # common wrappers (your project)
    try:
        if "sklearn" in wn or wn in (
            "sklearnclassifierwrapper",
            "sklearnclassifier",
        ):
            from pipeline_ml_training.classifier_wrapper import (
                SKLearnClassifierWrapper,
            )

            return _instantiate_with_fallback(
                SKLearnClassifierWrapper,
                classifier_obj,
                preprocessing_handler,
                model_spec,
            )
        if "river" in wn or wn in (
            "riverclassifierwrapper",
            "riverclassifier",
        ):
            from pipeline_ml_training.classifier_wrapper import (
                RiverClassifierWrapper,
            )

            return _instantiate_with_fallback(
                RiverClassifierWrapper,
                classifier_obj,
                preprocessing_handler,
                model_spec,
            )
        # fallback: dotted path
        if "." in w:
            Cls = _import_from_path(w)
            return _instantiate_with_fallback(
                Cls, classifier_obj, preprocessing_handler, model_spec
            )
    except Exception as e:
        raise RuntimeError(
            "Failed to instantiate wrapper '{}': {}".format(w, e)
        )

    raise ValueError("Unknown wrapper '{}'".format(w))


# -------------------------
# FEATURE EXTRACTOR FACTORY
# -------------------------
def build_feature_extractor(features_spec):
    if not isinstance(features_spec, dict):
        raise ValueError("features_spec must be a dict")
    try:
        from pipeline_ml_training.features import FeatureExtraction
    except Exception as e:
        raise RuntimeError("Failed to import FeatureExtraction: {}".format(e))

    proto_patterns = features_spec.get("proto_mapping_patterns")
    if proto_patterns and isinstance(proto_patterns, list):
        mapped = []
        for p in proto_patterns:
            if isinstance(p, dict):
                mapped.append((p.get("pattern"), p.get("value")))
            elif isinstance(p, (list, tuple)) and len(p) >= 2:
                mapped.append((p[0], p[1]))
            else:
                continue
        proto_patterns = mapped

    kwargs = {
        "default_label": features_spec.get("default_label"),
        "protocols_to_discard": features_spec.get("protocols_to_discard"),
    }
    kwargs = {k: v for k, v in kwargs.items() if v is not None}
    try:
        return FeatureExtraction(**kwargs)
    except TypeError:
        # fallback: core args
        core = {
            k: kwargs[k]
            for k in (
                "default_label",
                "protocols_to_discard",
                "columns_to_discard",
                "column_types",
            )
            if k in kwargs
        }
        return FeatureExtraction(**core)


# -------------------------
# PREPROCESSING WRAPPER BUILDER
# -------------------------
def build_preprocessing_wrapper(
    preprocessing_spec,
    experiment_name,
    base_models_dir,
    step_filename_template="{name}.bin",
):
    try:
        from pipeline_ml_training.preprocessing_wrapper import (
            PreprocessingWrapper,
        )
    except Exception as e:
        raise RuntimeError(
            "Failed to import PreprocessingWrapper: {}".format(e)
        )

    try:
        prep = PreprocessingWrapper(
            steps=[],
            experiment_name=experiment_name,
            base_models_dir=base_models_dir,
            step_filename_template=step_filename_template,
        )
    except TypeError:
        try:
            prep = PreprocessingWrapper(
                steps=[], experiment_name=experiment_name
            )
        except Exception as e:
            raise RuntimeError(
                "Failed to construct PreprocessingWrapper: {}".format(e)
            )

    steps = (
        preprocessing_spec.get("steps", [])
        if isinstance(preprocessing_spec, dict)
        else []
    )
    for s in steps:
        try:
            tr = build_transformer(s)
        except Exception as e:
            raise RuntimeError(
                "Failed to build transformer for step '{}': {}".format(
                    s.get("name"), e
                )
            )
        prep.add_step(s.get("name"), tr)
    return prep


# -------------------------
# DATASET LOADER BUILDER
# -------------------------
def build_loaders(root, dataset_loader_spec, seed=None):
    from pipeline_ml_training.dataset_wrapper import find_and_load_datasets

    batch_size = dataset_loader_spec.get("batch_size", 1000)
    prefix_regex = dataset_loader_spec.get("prefix_regex", r"^\d{3}")
    data_subdir = dataset_loader_spec.get("data_subdir", "data")

    loaders = find_and_load_datasets(
        root,
        batch_size=batch_size,
        prefix_regex=prefix_regex,
        data_subdir=data_subdir,
        seed=seed,
    )

    for key, loader in loaders.items():
        try:
            if "persist_cache_threshold" in dataset_loader_spec and hasattr(
                loader, "persist_cache_threshold"
            ):
                loader.persist_cache_threshold = dataset_loader_spec.get(
                    "persist_cache_threshold"
                )
        except Exception:
            pass
        try:
            if "cache_dir" in dataset_loader_spec and hasattr(
                loader, "cache_dir"
            ):
                loader.cache_dir = dataset_loader_spec.get("cache_dir")
        except Exception:
            pass
        try:
            if "labeled_filenames" in dataset_loader_spec and hasattr(
                loader, "labeled_filenames"
            ):
                loader.labeled_filenames = dataset_loader_spec.get(
                    "labeled_filenames"
                )
        except Exception:
            pass
        try:
            if "file_encoding" in dataset_loader_spec and hasattr(
                loader, "file_encoding"
            ):
                loader.file_encoding = dataset_loader_spec.get("file_encoding")
            if "file_errors" in dataset_loader_spec and hasattr(
                loader, "file_errors"
            ):
                loader.file_errors = dataset_loader_spec.get("file_errors")
        except Exception:
            pass
        try:
            if "shuffle_per_epoch" in dataset_loader_spec and hasattr(
                loader, "shuffle_per_epoch"
            ):
                loader.shuffle_per_epoch = dataset_loader_spec.get(
                    "shuffle_per_epoch"
                )
        except Exception:
            pass

    return loaders


# -------------------------
# factory
# -------------------------


def build_mixer(spec, loaders, rng):
    """
    Mixer builder for dataset mixing strategies.
    spec: dict with at least a "type" key.
    loaders: dataset loaders.
    rng: random number generator.
    """
    t = spec.get("type")
    # Import mixers from pipeline_ml_training.mixer
    try:
        from pipeline_ml_training.mixer import (
            SequenceMixer,
            RandomBatchesMixer,
            BalancedByLabelMixer,
        )
    except Exception as e:
        raise RuntimeError("Failed to import mixer classes: {}".format(e))

    if t == "sequence":
        return SequenceMixer(spec, loaders, rng)
    if t == "random_batches":
        return RandomBatchesMixer(spec, loaders, rng)
    if t == "balanced_by_label":
        return BalancedByLabelMixer(spec, loaders, rng)
    raise ValueError("Unknown mixer type '{}'".format(t))
