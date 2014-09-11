'''
Created on 11.09.2014

@author: mgr
'''

import sys
import ldap, ldap.sasl

from SambaPosix.LDAPEntry import LDAPEntry

class Command(object):
    '''
    classdocs
    '''

    Command = None

    def __init__(self, argv, parser, program_name):
        '''
        Constructor
        '''
        self.program_name = program_name
        self.setupUsage()
        parser.set_usage(self.usage_string)
        parser = self.setupOptions(parser)
        (self.opts, self.args) = parser.parse_args(argv)

        if len(self.args) < 1:
            sys.stderr.write(self.usage_string + "\n")
            indent = len(program_name) * " "
            sys.stderr.write(indent + "  for help use --help")
            return 2

        if self.args[0] != self.Command:
            raise RuntimeError("%s is handler for %s, but invoked by %s" % (self.__class__.__name__,self.Command,self.args[0]))
        self.args = self.args[1:]
        self.CommandPath = [self.Command]
        self.LDAP = None

    def setupOptions(self,parser):
        return parser

    def setupUsage(self):
        self.usage_string = "usage: %s %s [options]" % (self.program_name,self.Command)

    def dispatchCommand(self,prefix='do_'):
        cmd_name = self.args[0]
        self.CommandPath += [cmd_name]
        cmd = prefix+cmd_name
        self.args = self.args[1:]

        if hasattr(self, cmd):
            func = getattr(self, cmd)
            if hasattr(func, '__call__'):
                return func()

        raise ValueError("Unknown command %s" % " ".join(self.CommandPath))

    def connect(self):
        auth = ldap.sasl.gssapi("")
        self.LDAP = ldap.initialize(self.opts.url)
        self.LDAP.sasl_interactive_bind_s("",auth)
        self.trace("Connected to %s" % self.opts.url)

    def error(self,msg):
        indent = len(self.program_name) * " "
        sys.stderr.write(self.program_name + ": " + msg + "\n")
        sys.stderr.write(indent + "  for help use --help\n")

    def trace(self,msg, level = 3):
        if self.opts.verbose >= level:
            sys.stderr.write(msg + '\n')

    def result(self,msg):
        sys.stdout.write(msg + '\n')

    def search(self,query):
        if self.LDAP is None:
            self.connect()
        self.trace("Search at %s for %s" % (self.opts.base, query))
        results = self.LDAP.search_s(self.opts.base, ldap.SCOPE_SUBTREE, query)
        # we get those strange results without DN - referrals?
        results = [LDAPEntry(x) for x in results if x[0] is not None]
        return results
