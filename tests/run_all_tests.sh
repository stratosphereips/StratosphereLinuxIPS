#!/bin/bash
# clear the cache database
./slips.py -cc


# run all unit tests, -n *5 means distribute tests on 5 different process
# -s to see print statements as they are executed
python3  -m pytest tests/ --ignore="tests/test_dataset.py" --ignore="tests/test_daemon.py" --ignore="tests/test_database.py" -n 7 -p no:warnings -vv -s

# run db and daemon tests serially/using 1 worker
python3  -m pytest tests/test_database.py -p no:warnings -vv -s

# running serially because slips only supports running 1 daemon at a time
python3  -m pytest tests/test_daemon.py -p no:warnings -vv

# Close all redis-servers opened by the unit tests
python3 tests/destrctor.py

# clear cache before running the integration tests
./slips.py -cc


# the command to run dataset tests is separated from the rest because it takes so much time,
# so it's better to know and fix the failing unit tests from the above
# command before running the dataset tests
# distribute on 3 workers only because every worker will be spawning 10+ processes

python3 -m pytest -s tests/test_dataset.py -n 4 -p no:warnings -vv
./slips.py --killall
./slips.py -cc
