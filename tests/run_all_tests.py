import os

# clear the cache database
os.system('./slips.py -c slips.conf -cc')
os.system('./slips.py --killall ')

# run all unit tests, -n *5 means distribute tests on 5 different process
os.system('python3  -m pytest tests/ --ignore="tests/test_dataset.py" -n 5 -p no:warnings -v ')

# kill all redis servers before running the dataset tests
os.system('./slips.py --killall ')


# the command to run dataset tests is separated from the rest because it takes so much time,
# so it's better to know and fix the failing unit tests from the above
# command before running the dataset tests
os.system('python3 -m pytest tests/test_dataset.py -n 5 -p no:warnings -v -s')
