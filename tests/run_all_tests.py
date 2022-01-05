#!/usr/bin/env python3
import os
# clear the database
os.system('./slips.py -c slips.conf -cc')
# run all unit tests
os.system('python3 -m pytest tests/ --ignore="tests/test_dataset.py" -p no:warnings -vv ')
# test everything in our dataset
# the command to run dataset tests is separated from the rest because it takes so much time,
# so it's better to know and fix the failing unit tests from the above
# command before running the dataset tests
os.system('python3 -m pytest tests/test_dataset.py -p no:warnings -vv -s')
