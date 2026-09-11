"""
Restricted pickle deserialization for ML model/preprocessor/PCA artifacts.

Plain `pickle.load()` executes arbitrary code if the file was tampered
with, because unpickling can call any importable callable via the
GLOBAL/STACK_GLOBAL opcodes (e.g. `os.system`, `subprocess.Popen`,
`builtins.eval`). This module only allows globals that come from the ML
libraries Slips actually uses to store models (numpy, scipy, sklearn,
river) plus a small set of harmless builtins, so a malicious payload
that references anything else is rejected before it can run.
"""

import io
import pickle

SAFE_MODULE_PREFIXES = (
    "numpy",
    "sklearn",
    "scipy",
    "river",
    "collections",
    "copyreg",
    "modules.ml_online_model.ml_online_model",
)

SAFE_BUILTINS = {
    "object",
    "list",
    "dict",
    "tuple",
    "set",
    "frozenset",
    "complex",
    "slice",
    "range",
    "bytearray",
}


class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that only resolves an allowlisted set of globals."""

    def find_class(self, module: str, name: str):
        """
        Resolve a pickled global, refusing anything outside the ML
        library allowlist.

        :param module: dotted module path referenced by the pickle stream
        :param name: attribute name being looked up in that module
        :return: the resolved class/function
        """
        if module == "builtins":
            if name not in SAFE_BUILTINS:
                raise pickle.UnpicklingError(
                    f"Blocked potentially unsafe global during "
                    f"unpickling: builtins.{name}"
                )
        elif not any(
            module == prefix or module.startswith(prefix + ".")
            for prefix in SAFE_MODULE_PREFIXES
        ):
            raise pickle.UnpicklingError(
                f"Blocked potentially unsafe global during unpickling: "
                f"{module}.{name}"
            )
        return super().find_class(module, name)


def safe_pickle_load(file_handler):
    """
    Deserialize a pickle stream from an open binary file handler while
    blocking access to any global outside the ML library allowlist.

    :param file_handler: file object opened in binary read mode
    :return: the deserialized object
    """
    return RestrictedUnpickler(file_handler).load()


def safe_pickle_loads(data: bytes):
    """
    Deserialize a pickle byte string while blocking access to any
    global outside the ML library allowlist.

    :param data: raw pickle bytes
    :return: the deserialized object
    """
    return RestrictedUnpickler(io.BytesIO(data)).load()
