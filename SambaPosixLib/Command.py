'''
Created on 29.10.2014

@author: mgr
'''

import sys, os
from SambaPosixLib.Logger import Logger

class InvalidCommand(Exception):
    pass

class Command(object):
    '''
    classdocs
    '''


    def __init__(self,opts,oLDAP):
        '''
        Constructor
        '''
        self.opts = opts
        self.LDAP = oLDAP
        self.command = None
        if self.Usage is None:
            self._setupUsage("", False)
        self.Logger = Logger()

    @classmethod
    def optionGroup(cls, parser):
        return parser

    @classmethod
    def run(cls,opts,oLDAP):
        oCls = cls(opts,oLDAP)
        return oCls._do_run()

    def _do_run(self):
        try:
            return self.do_run()
        except InvalidCommand, e:
            raise InvalidCommand(self.usage(str(e)))

    def do_run(self):
        raise NotImplementedError("Please implement the main handler for %s" % self.__class__.__name__)

    def _setupUsage(self, path, leaf = False):
        program_name = os.path.basename(sys.argv[0])
        if not leaf:
            self.Usage = "usage: %s %s cmd [options]" % (program_name, path)
        else:
            self.Usage = "usage: %s %s [options]" % (program_name, path)

    def print_usage(self, msg, fail=False):
        if not fail:
            print msg
        else:
            sys.stderr.write(msg)
