#!/bin/bash
# clear the cache database
./slips.py -c slips.conf -cc
./slips.py --killall

# run all unit tests, -n *5 means distribute tests on 5 different process
python3  -m pytest tests/ --ignore="tests/test_dataset.py" -n 5 -p no:warnings -v

# kill all redis servers before running the dataset tests
./slips.py -k

# the command to run dataset tests is separated from the rest because it takes so much time,
# so it's better to know and fix the failing unit tests from the above
# command before running the dataset tests
# distribute on 3 workers only because every worker will be spawning around 10 processes
python3 -m pytest tests/test_dataset.py -n 3 -p no:warnings -v -s
./slips.py -k 
