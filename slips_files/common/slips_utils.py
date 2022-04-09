
# Must Import
import sys
# Your imports
import hashlib


class Utils(object):
    name = 'utils'
    description = 'Common functions used by different modules of slips.'
    authors = ['Alya Gomaa']
    output = []

    def __init__(self):
        pass

    def get_hash_from_file(self, filename):
        """
        Compute the sha256 hash of a file
        """
        # The size of each read from the file
        BLOCK_SIZE = 65536
        # Create the hash object, can use something other
        # than `.sha256()` if you wish
        file_hash = hashlib.sha256()
        # Open the file to read it's bytes
        with open(filename, 'rb') as f:
            # Read from the file. Take in the amount declared above
            fb = f.read(BLOCK_SIZE)
            # While there is still data being read from the file
            while len(fb) > 0:
                # Update the hash
                file_hash.update(fb)
                # Read the next block from the file
                fb = f.read(BLOCK_SIZE)
        return file_hash.hexdigest()

