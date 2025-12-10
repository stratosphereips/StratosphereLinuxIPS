import pickle
from pathlib import Path


class PreprocessingWrapper:
    def __init__(
        self,
        steps=None,
        experiment_name="default",
        base_models_dir="./experiments",
        step_filename_template="{name}.bin",
    ):
        """
        steps: List of (step_name, transformer) tuples
        experiment_name: name of the experiment to organize saved files
        base_models_dir: base directory to save/load models
        step_filename_template: template for step filenames when saving/loading
        """

        self.steps = steps if steps is not None else []
        self.experiment_name = experiment_name
        self.is_fitted = {name: False for name, _ in self.steps}
        self._has_been_fitted_once = False
        self.base_models_dir = Path(base_models_dir)
        self.step_filename_template = step_filename_template

    def add_step(self, name: str, transformer: object):
        if self._has_been_fitted_once:
            print(
                f"[WARNING] Adding new step '{name}' after fitting has started. Ensure order consistency."
            )
        self.steps.append((name, transformer))
        self.is_fitted[name] = False

    def partial_fit(self, X, y=None):
        """
        Fit transformers on first call, then use partial_fit if available on subsequent calls.
        Handles transformers with only fit or only partial_fit.
        """
        for name, transformer in self.steps:
            if transformer is None:
                raise AttributeError(
                    f"Transformer '{name}' is None, cannot fit."
                )

            # Decide which method to call
            if not self._has_been_fitted_once:
                # First time: use fit if available, else partial_fit
                method = getattr(transformer, "fit", None) or getattr(
                    transformer, "partial_fit", None
                )
            else:
                # Subsequent calls: use partial_fit if available, else fit
                method = getattr(transformer, "partial_fit", None) or getattr(
                    transformer, "fit", None
                )

            if method is None or not callable(method):
                raise AttributeError(
                    f"Transformer '{name}' has neither fit nor partial_fit."
                )

            # Call the method
            method(X, y)
            self.is_fitted[name] = True

        self._has_been_fitted_once = True

    def transform(self, X):
        """Apply fitted transformations in sequence."""
        for name, transformer in self.steps:
            if not self.is_fitted[name]:
                raise RuntimeError(
                    f"Step '{name}' was not fitted before transform()."
                )
            try:
                X = transformer.transform(X)
            except Exception as e:
                print(f"[ERROR] Transforming step '{name}' failed: {e}")
                raise
        return X

    def save(self, base_path=None):
        if base_path is None:
            base_path = (
                self.base_models_dir / self.experiment_name / "preprocessing"
            )
        else:
            base_path = Path(base_path)
        base_path.mkdir(parents=True, exist_ok=True)
        for name, transformer in self.steps:
            filename = self.step_filename_template.format(name=name)
            model_path = base_path / filename
            with open(model_path, "wb") as f:
                data = pickle.dumps(transformer)
                f.write(data)

    def load(self, base_path=None):
        if base_path is None:
            base_path = (
                self.base_models_dir / self.experiment_name / "preprocessing"
            )
        else:
            base_path = Path(base_path)
        if not base_path.exists():
            raise FileNotFoundError(
                f"Preprocessing directory {base_path} does not exist."
            )
        for name, transformer in self.steps:
            filename = self.step_filename_template.format(name=name)
            model_path = base_path / filename
            if not model_path.exists():
                raise FileNotFoundError(
                    f"Preprocessing step {name} not found at {model_path}"
                )
            with open(model_path, "rb") as f:
                loaded = pickle.load(f)
            self._replace_transformer(name, loaded)
            self.is_fitted[name] = True
        self._has_been_fitted_once = True

    def _replace_transformer(self, name: str, new_transformer: object):
        """Replace transformer in steps list."""
        self.steps = [
            (n, new_transformer if n == name else t) for n, t in self.steps
        ]

    def get_steps(self):
        return self.steps
