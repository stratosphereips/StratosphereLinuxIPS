# AGENTS.md

## Project overview
- Entry point: `slips.py` (starts the main process, spawns modules, runs in interactive/daemon modes).
- Core framework code lives in `slips/`, `slips_files/`, and `managers/`.
- Detection/analysis modules are in `modules/` (implement the `IModule` interface).
- Configuration is in `config/` (main config: `config/slips.yaml`).
- Tests live under `tests/` (unit + integration suites).
- Documentation is in `docs/` (see `docs/contributing.md` for contribution workflow, branching, and PR expectations).
- UIs/tools: `SlipsWeb/`, `webinterface/`, `webinterface.sh`, and `kalipso.sh`.

## Build and test commands
- Run locally (no build step):
  - `./slips.py -e 1 -f dataset/test7-malicious.pcap -o output_dir`
- Build the Docker image (from `docs/installation.md`):
  - `docker build --no-cache -t slips -f docker/Dockerfile .`
  - If build networking fails: `docker build --network=host --no-cache -t slips -f docker/Dockerfile .`
- Run the Docker image:
  - `docker run -it --rm --net=host slips`

## Code style guidelines
- Python formatting is enforced via pre-commit:
  - Black with `--line-length 79` (see `.pre-commit-config.yaml`).
  - Ruff is used for linting and autofixes.
- Keep docstrings at the top of files where present (pre-commit `check-docstring-first`).
- Maintain clean whitespace (no trailing whitespace, final newline).
- Follow existing module patterns (`IModule` in `slips_files/common/abstracts/module.py`).

## Testing instructions
- The canonical test runner is `tests/run_all_tests.sh` (runs unit tests then integration tests).
- Equivalent manual sequence (from `tests/run_all_tests.sh`):
  - `./slips.py -cc`
  - `printf "0" | ./slips.py -k`
  - `python3 -m pytest tests/ --ignore="tests/integration_tests" -n 7 -p no:warnings -vvvv -s`
  - `python3 tests/destrctor.py`
  - `./slips.py -cc`
  - `printf "0" | ./slips.py -k`
  - `python3 -m pytest -s tests/integration_tests/test_portscans.py -p no:warnings -vv`
  - `python3 -m pytest -s tests/integration_tests/test_dataset.py -p no:warnings -vv`
  - `python3 -m pytest -s tests/integration_tests/test_config_files.py -p no:warnings -vv`
  - `printf "0" | ./slips.py -k`
  - `./slips.py -cc`
