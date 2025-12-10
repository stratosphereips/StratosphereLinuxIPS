# pipeline_ml_training/minimal_mapper.py
"""
Minimal mappers returning classes (not instances).

Exports:
 - get_transformer_class(type_name)
 - get_classifier_class(classifier_type)
 - prepare_river_nested_model_params(params)
 - get_wrapper_class(wrapper_name)
 - get_mixer_class(mixer_type)

Dotted-path import supported. Module search lists are intentionally small.
"""

import importlib


# -------------------------
# helpers
# -------------------------
def _import_from_path(path):
    parts = path.split(".")
    if len(parts) < 2:
        raise ImportError("dotted path expected, got: {}".format(path))
    module = ".".join(parts[:-1])
    name = parts[-1]
    mod = importlib.import_module(module)
    return getattr(mod, name)


def _find_in_modules(name, modules):
    # try exact and capitalized
    candidates = [name, name[0].upper() + name[1:] if name else name]
    for m in modules:
        try:
            mod = importlib.import_module(m)
        except Exception:
            continue
        for c in candidates:
            if hasattr(mod, c):
                return getattr(mod, c)
    return None


# -------------------------
# transformer mapper
# -------------------------
def get_transformer_class(type_name):
    if not type_name:
        raise ValueError("type_name required")

    # dotted path
    if "." in type_name:
        return _import_from_path(type_name)

    modules = [
        "sklearn.preprocessing",
        "sklearn.decomposition",
        "sklearn.impute",
    ]
    Cls = _find_in_modules(type_name, modules)
    if Cls is not None:
        return Cls
    raise ValueError(
        "Transformer '{}' not found (tried sklearn modules)".format(type_name)
    )


# -------------------------
# classifier mapper
# -------------------------
def get_classifier_class(classifier_type):
    if not classifier_type:
        raise ValueError("classifier_type required")

    # dotted path
    if "." in classifier_type:
        return _import_from_path(classifier_type)

    sklearn_modules = [
        "sklearn.linear_model",
        "sklearn.ensemble",
        "sklearn.svm",
        "sklearn.naive_bayes",
        "sklearn.tree",
    ]
    Cls = _find_in_modules(classifier_type, sklearn_modules)
    if Cls is not None:
        return Cls

    # try a small set of river modules
    river_modules = [
        "river.tree",
        "river.ensemble",
        "river.linear_model",
    ]
    Cls = _find_in_modules(classifier_type, river_modules)
    if Cls is not None:
        return Cls

    # try xgboost common alias
    try:
        if classifier_type.lower() in (
            "xgbclassifier",
            "xgboost",
            "xgboostclassifier",
            "xgb",
        ):
            from xgboost import XGBClassifier

            return XGBClassifier

        # Try to find in xgboost module using _find_in_modules
        Cls = _find_in_modules(classifier_type, ["xgboost"])
        if Cls is not None:
            return Cls
    except Exception:
        pass

    raise ValueError("Classifier '{}' not found".format(classifier_type))


def prepare_river_nested_model_params(params):
    """
    If params contains {'model': {'type': ..., 'params': {...}}}, instantiate inner model
    and replace params['model'] with the instantiated object. Returns mutated params.
    """
    if not isinstance(params, dict):
        return params
    nested = params.get("model")
    if not isinstance(nested, dict):
        return params
    inner_type = nested.get("type")
    inner_params = nested.get("params", {}) or {}
    if not inner_type:
        raise ValueError("Nested model spec missing 'type'")
    # dotted or search river submodules
    try:
        if "." in inner_type:
            InnerCls = _import_from_path(inner_type)
        else:
            InnerCls = _find_in_modules(
                inner_type,
                ["river.tree", "river.ensemble", "river.linear_model"],
            )
            if InnerCls is None:
                InnerCls = _import_from_path(inner_type)
        params["model"] = InnerCls(**inner_params)
        return params
    except Exception as e:
        raise RuntimeError(
            "Failed to instantiate nested river model '{}': {}".format(
                inner_type, e
            )
        )


# -------------------------
# wrapper mapper
# -------------------------
def get_wrapper_class(wrapper_name):
    if not wrapper_name:
        raise ValueError("wrapper_name required")
    # dotted path
    if "." in wrapper_name:
        return _import_from_path(wrapper_name)

    try:
        mod = importlib.import_module(
            "pipeline_ml_training.classifier_wrapper"
        )
    except Exception:
        raise RuntimeError("Failed to import local classifier_wrapper module")

    wn = wrapper_name.lower()
    if "sklearn" in wn:
        if hasattr(mod, "SKLearnClassifierWrapper"):
            return getattr(mod, "SKLearnClassifierWrapper")
    if "river" in wn:
        if hasattr(mod, "RiverClassifierWrapper"):
            return getattr(mod, "RiverClassifierWrapper")

    # try direct attribute name
    if hasattr(mod, wrapper_name):
        return getattr(mod, wrapper_name)

    raise ValueError("Wrapper '{}' not found".format(wrapper_name))


# -------------------------
# mixer mapper
# -------------------------
def get_mixer_class(mixer_type):
    if not mixer_type:
        raise ValueError("mixer_type required")
    # dotted path
    if "." in mixer_type:
        return _import_from_path(mixer_type)
    try:
        mod = importlib.import_module("pipeline_ml_training.mixers")
    except Exception:
        raise RuntimeError("Failed to import built-in mixers module")

    if mixer_type == "sequence":
        return getattr(mod, "SequenceMixer")
    if mixer_type == "random_batches":
        return getattr(mod, "RandomBatchesMixer")
    if mixer_type == "balanced_by_label":
        return getattr(mod, "BalancedByLabelMixer")
    raise ValueError("Unknown mixer type '{}'".format(mixer_type))
