import os
# clear the database
os.system('./slips.py -c slips.conf -cc')
# run all unit tests
<<<<<<< HEAD
os.system('python3 -m pytest tests/ -n 5 --ignore="tests/test_dataset.py" -p no:warnings -v ')
=======
os.system('python3 -m pytest tests/ --ignore="tests/test_dataset.py" -p no:warnings -v ')
>>>>>>> develop
# test everything in our dataset
# the command to run dataset tests is separated from the rest because it takes so much time,
# so it's better to know and fix the failing unit tests from the above
# command before running the dataset tests
<<<<<<< HEAD
os.system('python3 -m pytest tests/test_dataset.py -n 5 -p no:warnings -v -s')
=======
os.system('python3 -m pytest tests/test_dataset.py -p no:warnings -v -s')
>>>>>>> develop
