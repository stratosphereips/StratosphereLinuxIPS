# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder.
#    cp modules/template/template.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the module, description and author in the variables
# 5. The file name of the python module (template.py) MUST be the same as the name of the folder (template)
# 6. The variable 'name' MUST have the public name of this module. This is used to ignore the module
# 7. The name of the class MUST be 'Module', do not change it.

# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
import sys

# Your imports
import os
import yara

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'leak_detector'
    description = 'Detect leaks of data in the traffic'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        self.config = config
        # Start the DB
        __database__.start(self.config)
        self.timeout = None
        # this module is only loaded when a pcap is given get the pcap path
        try:
            self.pcap = sys.argv[sys.argv.index('-f')+1]
        except NameError:
            # this error is raised when we start this module in the unit tests so there's no argv
            # ignore it
            pass
        self.yara_rules_path = 'modules/leak_detector/yara_rules/rules/'
        self.compiled_yara_rules_path = 'modules/leak_detector/yara_rules/compiled/'
        # this file is used for writing all the evidence detected by this module
        self.output_file = 'output/leak_detection.txt'
        # create the evidence file if not there
        if not os.path.exists(self.output_file):
            open(self.output_file,'w').close()

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f"{levels}|{self.name}|{text}")

    def set_evidence_yara_match(self, info:dict ):
        """
        This function is called when yara finds a match
        :param info: a dict with info about the matched rule, example keys 'tags', 'matches', 'rule', 'strings' etc.
        """

        rule = info.get('rule')
        meta = info.get('meta',False)
        # strings is a list of tuples containing information about the matching strings.
        # Each tuple has the form: (<offset>, <string identifier>, <string data>).
        strings = info.get('strings')
        description = meta.get('description')
        # author = meta.get('author')
        # reference = meta.get('reference')
        # organization = meta.get('organization')

        evidence = f'{rule} detected in {self.pcap}. Rule description: {description}.\nMatches:\n'
        for match in strings:
            offset, string_found, matched_bytes = match[0], match[1], match[2]
            evidence+= f'At offset {offset} found {string_found} matched bytes: {matched_bytes}\n'

        with open(self.output_file,'a') as f:
            f.write(f'{evidence}\n')

    def compile_and_save_rules(self):
        """
        Compile and save all yara rules in the compiled_yara_rules_path
        """
        for yara_rule in os.listdir(self.yara_rules_path):
            # get the complete path of the rule
            rule_path = os.path.join(self.yara_rules_path, yara_rule)
            # ignore yara_rules/compiled/
            if not os.path.isfile(rule_path):
                continue
            # compile the rule
            compiled_rule = yara.compile(filepath=rule_path)
            # save the compiled rule
            compiled_rule.save(os.path.join(self.compiled_yara_rules_path, f'{yara_rule}_compiled'))

    def run(self):
        try:
            # if we we don't have compiled rules, compile them
            if not os.path.exists(self.compiled_yara_rules_path):
                os.mkdir(self.compiled_yara_rules_path)
                self.compile_and_save_rules()

            for compiled_rule in os.listdir(self.compiled_yara_rules_path):
                compiled_rule_path = os.path.join(self.compiled_yara_rules_path, compiled_rule)
                # load the compiled rules
                rule = yara.load(compiled_rule_path)
                # call set_evidence_yara_match when a match is found
                matches = rule.match(self.pcap, callback=self.set_evidence_yara_match, which_callbacks=yara.CALLBACK_MATCHES)

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on the run() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
