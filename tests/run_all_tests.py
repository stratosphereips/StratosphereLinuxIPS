import os
# clear the database
os.system('./slips.py -c slips.conf -cc')
# run all tests
os.system('python3 -m pytest tests/ -p no:warnings -v')
