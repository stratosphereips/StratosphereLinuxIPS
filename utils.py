#!/usr/bin/python -u
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
# Authors: 
# Ondrej Lukas - ondrej.lukas95@gmail.com, lukasond@fel.cvut.cz
# Sebastian Garcia - sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com

import signal
import whois
import time
import sys


class SignalHandler(object):
    """Used for asynchronous control of the program -e.g. premature interrupting with CTRL+C """
    def __init__(self, process):
        self.process = process
        self.active = True

    def register_signal(self, signal_n):
        """Adds signal  to the handler to proccess it"""
        signal.signal(signal_n, self.process_signal)

    def process_signal(self, signal, frame):
        if self.active:
            self.process.queue.close()
            try:
                print "\nInterupting SLIPS"
                time.sleep(0.5)
            except Exception:
                print "Sth went wrong"
            time.sleep(1)
            sys.exit(0)


class WhoisHandler(object):
    """This class is used for getting the whois information.
     Since queries to whois service takes too much time
     it stores all the information in the redis database with the prefix whois-<ip>"""

    def __init__(self, db):
        self.db = db

    def get_whois_data(self, ip):
        desc = self.db.getWhoisData()
        if desc is not None:
            return desc
        else:
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
            self.db.setWhoisData(ip, desc)
            return desc


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
