# modules/flowmldetection/pipeline_ml_training/testing/conftest.py
import os
import sys

# Add the flowmldetection folder to sys.path so "pipeline_ml_training" is importable.
# Path computed relative to this file: ../../  => modules/flowmldetection
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

if ROOT not in sys.path:
    # insert at front so tests' local package wins over any installed package
    sys.path.insert(0, ROOT)
