import os
# clear the database
os.system('./slips.py -c slips.conf -cc')
# run all unit tests
# os.system('python3 -m pytest tests/ -n 10 --ignore="tests/test_dataset.py" -p no:warnings -v ')
# test everything in our dataset
# the command to run dataset tests is separated from the rest because slips will quit if one instance is using a db and another instance is trying to use
# the same db. so dataset tests are designed to run on their own
os.system('python3 -m pytest tests/test_dataset.py -n 5 -p no:warnings -v -s')
