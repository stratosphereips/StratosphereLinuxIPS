#!/usr/bin/python -u
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
# Authors: 
# Ondrej Lukas - ondrej.lukas95@gmail.com, lukasond@fel.cvut.cz
# Sebastian Garcia - sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com

import signal
import re
import time
import sys

class SignalHandler(object):
    """Used for asynchronous control of the program -e.g. premature interrupting with CTRL+C """
    def __init__(self,process):
            self.process = process
            self.active =True;

    def register_signal(self, signal_n):
        """Adds signal  to the handler to proccess it"""
        signal.signal(signal_n,self.process_signal)

    def process_signal(self,signal, frame):
        #print "signal:{},frame:{},time:{}.".format(signal,frame,datetime.now())
        if(self.active):
            self.process.queue.close()
            try:
                print "\nInterupting SLIPS"
                self.process.ip_handler.print_alerts()
                time.sleep(0.5)
            except Exception:
                print "Sth went wrong"
            time.sleep(1)
            sys.exit(0)


class WhoisHandler(object):
    """This class is used for getting the whois information. Since queries to whois service takes too much time it stores all the information localy in the txt file.
     Structure of the file:
     [ip address][TAB][Description][\n]"""

    def __init__(self,whois_file):
        self.whois_data = {}
        self.filename = whois_file
        self.new_item = False
        try:
            with open(whois_file) as f:
                for line in f:
                    s = re.split("\t",line.strip())
                    if len(s) > 1:
                        self.whois_data[s[0]] = s[1]
            print "Whois file '{}' loaded successfully".format(whois_file)            
        except IOError:
            print "Whois informaton file:'{}' doesn't exist!".format(self.filename)
            pass
    
    def get_whois_data(self,ip):
        #do we have it in the cache?
        try:
            import ipwhois
        except ImportError:
            print 'The ipwhois library is not install. pip install ipwhois'
            return False
        # is the ip in the cache
        try:
            desc = self.whois_data[ip]
            return desc
        except KeyError:
            # Is not, so just ask for it
            try:
                obj = ipwhois.IPWhois(ip)
                data = obj.lookup_whois()
                try:
                    desc = data['nets'][0]['description'].strip().replace('\n',' ') + ',' + data['nets'][0]['country']
                except AttributeError:
                    # There is no description field
                    desc = ""
                except TypeError:
                    #There is a None somewhere, just continue..
                    desc = ""
            except ValueError:
                # Not a real IP, maybe a MAC
                desc = 'Not an IP'
                pass
            except IndexError:
                # Some problem with the whois info. Continue
                pass        
            except ipwhois.IPDefinedError as e:
                if 'Multicast' in e:
                    desc = 'Multicast'
                desc = 'Private Use'
            except ipwhois.WhoisLookupError:
                print 'Error looking the whois of {}'.format(ip)
                # continue with the work\
                pass
            # Store in the cache
            self.whois_data[ip] = desc
            self.new_item = True;
            return desc
        except Exception as inst:
            print '\tProblem with get_whois_data() in utils.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)


    def store_whois_data_in_file(self):
        """Writes whois information in the file"""
        if self.new_item:
            f = open(self.filename,"w")
            for item in self.whois_data.items():
                f.write('{}\t{}\n'.format(item[0],item[1]));
            f.close();
        else:
            print "No new stuff in the dictionary"

def deep_getsizeof(o, ids):
    """
    https://code.tutsplus.com/tutorials/understand-how-much-memory-your-python-objects-use--cms-25609
    Find the memory footprint of a Python object
    This is a recursive function that drills down a Python object graph
    like a dictionary holding nested dictionaries with lists of lists
    and tuples and sets.
    The sys.getsizeof function does a shallow size of only. It counts each
    object inside a container as pointer only regardless of how big it
    really is.
    :param o: the object
    :param ids:
    :return:
    """
    d = deep_getsizeof
    if id(o) in ids:
        return 0
    r = getsizeof(o)
    ids.add(id(o))
    if isinstance(o, str) or isinstance(0, unicode):
        return r
    if isinstance(o, Mapping):
        return r + sum(d(k, ids) + d(v, ids) for k, v in o.iteritems())
    if isinstance(o, Container):
        return r + sum(d(x, ids) for x in o)
    return r 
