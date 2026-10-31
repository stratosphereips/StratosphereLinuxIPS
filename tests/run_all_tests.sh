#!/bin/bash
# clear the cache database
./slips.py -cc

# run all unit tests, -n *5 means distribute tests on 5 different process
# -s to see print statements as they are executed
python3  -m pytest tests/unit/ --ignore="tests/integration" -n 7 -p no:warnings -vvvv -s

# clear cache before running the integration tests
./slips.py -cc

# auto-discover integration tests without Bash 4-only mapfile
while IFS= read -r test_file; do
    python3 -m pytest -s "$test_file" -n 3 -p no:warnings -vv
done < <(find tests/integration -type f -name 'test_*.py' | sort)


./slips.py -cc
