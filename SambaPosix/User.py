'''
Created on 11.09.2014

@author: mgr
'''

from SambaPosix.Command import Command
from optparse import OptionGroup

class User(Command):
    '''
    classdocs
    '''

    Command = "user"

    def __init__(self, argv, parser, program_name):
        '''
        Constructor
        '''
        Command.__init__(self, argv, parser, program_name)

        if len(self.args) < 1:
            self.error("missing command for user maintenance")
            raise RuntimeError("Invalid usage")

        self.dispatchCommand()

    def setupUsage(self):
        self.usage_string = "usage: %s %s command [options]" % (self.program_name,self.Command)

    def setupOptions(self, parser):
        group = OptionGroup(parser,"Posix user accounts")
        group.add_option("-u", "--uid", dest="uid", help="set numerical user ID", metavar="UID")
        group.add_option("-U", "--user", dest="user", help="choose user name", metavar="NAME")
        group.add_option("-g", "--gid", dest="gid", help="set numerical group ID of primary group", metavar="GID")
        group.add_option("-G", "--group", dest="group", help="set group name of primary group", metavar="NAME")
        group.add_option("", "--gecos", dest="gecos", help="set gecos", metavar="NAME")
        group.add_option("", "--shell", dest="shell", help="set shell", metavar="PATH")
        group.add_option("", "--home", dest="home", help="set home directory", metavar="PATH")
        parser.add_option_group(group)
        return parser

    def formatAsGetent(self,entry):
        out = []
        out += [entry.getSingleValue('uid')]
        out += ['x']
        out += [entry.getSingleValue('uidNumber')]
        out += [entry.getSingleValue('primaryGroupID')]
        out += [entry.getSingleValue('gecos')]
        out += [entry.getSingleValue('unixHomeDirectory')]
        out += [entry.getSingleValue('loginShell')]

        return ":".join([x if x is not None else "" for x in out])

    def do_show(self):
        if len(self.args) > 0:
            accounts = self.args
        elif self.opts.user is not None:
            accounts = [self.opts.user]
        else: accounts = None
        if accounts is None and self.opts.uid is not None:
            entries = self.search('(&(objectClass=posixAccount)(uidNumber=%s))' % self.opts.uid)
            accounts = []
            for record in entries:
                if 'sAMAccountName' in record:
                    accounts += record['sAMAccountName']
        if accounts is None:
            self.error("No user specified to show")
            return
        for user in accounts:
            entries = self.search('(&(sAMAccountName=%s)(objectClass=user))' % user)
            if len(entries) < 1:
                self.result("No matching users for %s" % user)
            elif len(entries) > 1:
                self.result("Error: %d matching users for %s" % (len(entries),user))
            else:
                entry = entries[0]
                if not entry.hasAttribute('objectClass', 'posixAccount'):
                    self.result("%s: no POSIX extensions" % user)
                else:
                    self.result(self.formatAsGetent(entry))
                    if 'userPassword' in entry or 'unixUserPassword' in entry:
                        self.result("#%s has unix password entries set!" % user)

    def do_getent(self):
        accounts = self.search('(objectClass=posixAccount)')
        for entry in accounts:
            self.result(self.formatAsGetent(entry))
