#!/bin/bash
# clear the cache database
./slips.py -cc
# close all open redis servers
printf "0" | ./slips.py -k

# run all unit tests, -n *5 means distribute tests on 5 different process
# -s to see print statements as they are executed
python3  -m pytest tests/ --ignore="tests/integration_tests" -n 7 -p no:warnings -vvvv -s

# Close all redis-servers opened by the unit tests
python3 tests/destrctor.py

# clear cache before running the integration tests
./slips.py -cc

# close all open redis servers
printf "0" | ./slips.py -k

# the command to run dataset tests is separated from the rest because it takes so much time,
# so it's better to know and fix the failing unit tests from the above
# command before running the dataset tests
# distribute on 3 workers only because every worker will be spawning 10+ processes

python3 -m pytest -s tests/integration_tests/test_portscans.py  -p no:warnings -vv
python3 -m pytest -s tests/integration_tests/test_dataset.py -p no:warnings -vv
python3 -m pytest -s tests/integration_tests/test_config_files.py  -p no:warnings -vv

printf "0" | ./slips.py -k

./slips.py -cc
