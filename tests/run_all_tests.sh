#!/bin/bash
# clear the cache database
./slips.py -cc
./slips.py --killall

# run all unit tests, -n *5 means distribute tests on 5 different process
# -s to see print statements as they are executed
python3  -m pytest tests/ --ignore="tests/test_dataset.py" --ignore="tests/test_database.py" -n 7 -p no:warnings -vv -s
# run db tests serially/using 1 worker
python3  -m pytest tests/test_database.py -n 1 -p no:warnings -vv -s --dist=loadfile

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
