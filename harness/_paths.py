"""
_paths.py — one place that knows the repository layout.

The repo is organised as:
    repo/
      src/       C sources
      bin/       compiled C binaries (built by the top-level Makefile)
      harness/   Python (this directory)
      results/   generated metrics, logs and figures

Every Python module imports this to find the binaries and the results folder,
so moving the tree or running from any directory keeps working.
"""
import os

HARNESS = os.path.dirname(os.path.abspath(__file__))   # .../repo/harness
REPO    = os.path.dirname(HARNESS)                      # .../repo
BIN     = os.path.join(REPO, "bin")                     # compiled C binaries live here
RESULTS = os.path.join(REPO, "results")                 # all generated outputs go here
os.makedirs(RESULTS, exist_ok=True)                     # make sure results/ exists

def binary(name):
    """Absolute path to a compiled C tool, e.g. binary('ids_runner')."""
    return os.path.join(BIN, name)
