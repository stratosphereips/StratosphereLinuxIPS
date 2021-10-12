# File containing some abstract definitions for slips


# This is the abstract Module class to check against. Do not modify
class Module(object):
    name = ''
    description = 'Template abstract module'
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
        except ArgumentErrorCallback as e:
            print('error')
