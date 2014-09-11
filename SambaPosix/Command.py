'''
Created on 11.09.2014

@author: mgr
'''

import sys
import ldap, ldap.sasl
import re, string

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
        self.sanitizeOptions()

    def setupOptions(self,parser):
        return parser

    def setupUsage(self):
        self.usage_string = "usage: %s %s [options]" % (self.program_name,self.Command)

    def sanitizeOptions(self):
        return True

    def checkPOSIXID(self,val):
        if val is None: return True
        if not re.match('^[0-9]+$',val): return False
        if int(val) > 65535: return False
        return True

    def checkPosixName(self,val):
        if val is None: return True
        # FIXME: should be NAME_REGEX
        if not re.match('^[_.A-Za-z0-9][-\@_.A-Za-z0-9]*\$?$',val): return False
        # FIXME: should be LOGIN_NAME_MAX
        if len(val) > 255: return False
        return True

    def checkPosixPath(self,val):
        if val is None: return True
        # must be absolute
        if not val[0] == '/': return False
        # find non-printables
        if not all(c in string.printable for c in val):
            return False
        # this would break getent
        if re.search(':',val):
            return False
        # FIXME: should be PATH_MAX
        if len(val) > 1024: return False
        return True

    def checkGecos(self,val):
        if val is None: return True
        # find non-printables
        if not all(c in string.printable for c in val):
            return False
        # this would break getent
        if re.search(':',val):
            return False
        # FIXME: no idea what may be a good length
        if len(val) > 1024: return False
        return True

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

    def error(self,msg):
        indent = len(self.program_name) * " "
        sys.stderr.write(self.program_name + ": " + msg + "\n")
        sys.stderr.write(indent + "  for help use --help\n")

    def trace(self,msg, level = 3):
        if self.opts.verbose >= level:
            sys.stderr.write(msg + '\n')

    def ldif(self,msg):
        sys.stdout.write(msg+'\n')

    def result(self,msg):
        sys.stdout.write(msg + '\n')

    def connect(self):
        auth = ldap.sasl.gssapi("")
        self.LDAP = ldap.initialize(self.opts.url)
        self.LDAP.sasl_interactive_bind_s("",auth)
        self.trace("Connected to %s" % self.opts.url)

    def search(self,query):
        if self.LDAP is None:
            self.connect()
        self.trace("Search at %s for %s" % (self.opts.base, query))
        results = self.LDAP.search_s(self.opts.base, ldap.SCOPE_SUBTREE, query)
        # we get those strange results without DN - referrals?
        results = [LDAPEntry(x) for x in results if x[0] is not None]
        return results

    def readDN(self,dn):
        if self.LDAP is None:
            self.connect()
        self.trace("Read entry %s" % (dn))
        results = self.LDAP.search_s(dn, ldap.SCOPE_BASE)
        if len(results) > 1:
            raise IndexError("Reading DN %s yielded %d results" % (dn, len(results)))
        if len(results) < 1:
            return None
        return LDAPEntry(results[0])

    def modify(self,dn,modlist):
        if self.opts.dry_run:
            self.ldif("dn: %s" % dn)
            self.ldif("changetype: modify")
            first = True
            for m in modlist:
                if not first:
                    self.ldif('-')
                if m[0] == ldap.MOD_ADD:
                    self.ldif("add: %s" % m[1])
                elif m[0] == ldap.MOD_DELETE:
                    self.ldif("delete: %s" % m[1])
                elif m[0] == ldap.MOD_REPLACE:
                    self.ldif("replace: %s" % m[1])
                else:
                    raise ValueError("Unknown action for changetype modify!")
                self.ldif("%s: %s" % (m[1],m[2]))
                first = False
        else:
            self.LDAP.modify_s(dn, modlist)
