# AGENTS.md

## 1. Project Overview

- Entry point: `slips.py`
  - Starts the main process
  - Spawns modules
  - Supports interactive and daemon modes

- Core code directories:
  - `slips/`
  - `slips_files/`
  - `managers/`

- Detection modules:
  - Located in `modules/`
  - Must implement `IModule` from:
    `slips_files/common/abstracts/module.py`

- Configuration:
  - Main file: `config/slips.yaml`

- Tests:
  - Located in `tests/`
  - Includes unit and integration tests

- Documentation:
  - Located in `docs/`
  - Contribution guide: `docs/contributing.md`

- UI / tools:
  - `SlipsWeb/`
  - `webinterface/`
  - `webinterface.sh`
  - `kalipso.sh`

- Repository root:
  - All commands MUST be executed from `StratosphereLinuxIPS/`

---

## 2. Build and Run

### to run slips locally
./slips.py -e 1 -f dataset/test7-malicious.pcap -o output_dir

### Build Docker image
docker build --no-cache -t slips -f docker/Dockerfile .

- If networking fails:

docker build --network=host --no-cache -t slips -f docker/Dockerfile .

### Run Docker container
docker run -it --rm --net=host slips

## 3. Code Style Rules

These rules MUST be followed:

- No trailing whitespace
- File must end with a newline
- Docstring must be the first statement in a file (if present)
- Avoid using environment variables, use variables from slips/config.yaml instead.

### Paths:
- NEVER use absolute paths
- ALWAYS use relative paths
### Files:
- If a non-debug file is created → MUST be added with git add
### Documentation:
If a feature is added → MUST update relevant docs in docs/
### Functions:
- Every new function MUST include a docstring
Docstrings MUST include:
- Short description
- Parameters (if applicable)
- Return value (if applicable)

## 4. Testing
- Canonical test runner
tests/run_all_tests.sh
## 5. Unit Test Update Workflow

When instructed to "update unit tests", follow EXACTLY:

Step 1 — Run tests
python3 -m pytest tests/unit/ \
  --ignore="tests/integration_tests" \
  -n 7 -p no:warnings -vvvv -s

Step 2 — Identify failures
Collect ALL failing tests

Step 3 — Fix tests
Update failing tests ONE BY ONE
Do NOT batch fixes

Step 4 — Add missing tests for new files
For every new source file in the branch:

- Mirror its directory under tests/unit/

- C/reate file:
test_<filename>.py
- Add unit tests for that file

Step 5 — Add tests for new functions
- Identify functions added in this branch (not in origin/develop)
- Add unit tests for each new function

Step 6 — Test structure rules
- MUST use @pytest.mark.parametrize when applicable

EACH test MUST:
Start with object creation using module_factory

Step 7 — Re-run tests
Run the same pytest command again
Ensure ALL tests pass

Step 8 — Git tracking
If new test files were created → run:
git add <files>

Step 9 — Failure fallback
If tests are still failing and cannot be fixed:
STOP
Report the issue

## 6. Custom Instructions
ALSO apply rules from:
private/AGENTS.md

If conflicts occur:
Prefer private/AGENTS.md
