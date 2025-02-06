# This file is copy and paste from original Slip repository
# to keep the originals building
# https://github.com/stratosphereips/StratosphereLinuxIPS/blob/5015990188f21176224e093976f80311524efe4e/slips_files/common/abstracts.py
# --------------------------------------------------------------------------------------------------

# File containing some abstract definitions for slips


# This is the abstract Module class to check against. Do not modify
class Module(object):
    name = ''
    description = 'Template abstract originals'
    authors = ['Template abstract Author']
    output = []

    def __init__(self):
        pass

    def usage(self):
        print('Usage')

    def help(self):
        print('Help')

    def run(self):
        try:
            print('test')
        except Exception as e:
            print('error')
