#!/bin/bash
# clear the cache database
./slips.py -cc
# close all open redis servers
printf "0" | ./slips.py -k

# run all unit tests, -n *5 means distribute tests on 5 different process
# -s to see print statements as they are executed
python3  -m pytest tests/ --ignore="tests/test_daemon.py" --ignore="tests/test_database.py" --ignore="tests/integration_tests" -n 7 -p no:warnings -vvvv -s --full-trace

## run db and daemon tests serially/using 1 worker
python3  -m pytest tests/test_database.py -p no:warnings -vvvv -s

# running serially because slips only supports running 1 daemon at a time
python3  -m pytest tests/test_daemon.py -p no:warnings -vvvv -s

# Close all redis-servers opened by the unit tests
python3 tests/destrctor.py

# clear cache before running the integration tests
./slips.py -cc

# close all open redis servers
printf "0" | ./slips.py -k
#
# the command to run dataset tests is separated from the rest because it takes so much time,
# so it's better to know and fix the failing unit tests from the above
# command before running the dataset tests
# distribute on 3 workers only because every worker will be spawning 10+ processes

python3 -m pytest tests/integration_tests/test_dataset.py -p no:warnings -vvvv -s

python3 -m pytest tests/integration_tests/test_config_files.py -p no:warnings -vvvv -s
printf "0" | ./slips.py -k
./slips.py -cc
