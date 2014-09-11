'''
Created on 11.09.2014

@author: mgr
'''

from SambaPosix.Command import Command
from optparse import OptionGroup

class Group(Command):
    '''
    classdocs
    '''

    Command = "group"

    def __init__(self, argv, parser, program_name):
        '''
        Constructor
        '''
        Command.__init__(self, argv, parser, program_name)

        if len(self.args) < 1:
            self.error("missing command for group maintenance")
            raise RuntimeError("Invalid usage")

        self.dispatchCommand()

    def setupUsage(self):
        self.usage_string = "usage: %s %s command [options]" % (self.program_name,self.Command)

    def setupOptions(self, parser):
        group = OptionGroup(parser,"Posix groups")
        group.add_option("-g", "--gid", dest="gid", help="set numerical group ID", metavar="GID")
        parser.add_option_group(group)
        return parser

    def resolveMembers(self,entry, recursive = True):
        members = []
        for dn in entry.values('member'):
            member = self.readDN(dn)
            if member is None:
                self.error("Group member %s does not exist" % dn)
            else:
                if member.hasAttribute('objectClass','user'):
                    if member.hasAttribute('objectClass','posixAccount'):
                        t = member.getSingleValue('uid')
                        if t is None:
                            t = member.getSingleValue('sAMAccountName')
                        members += [t]
                    else:
                        members += ['*' + member.getSingleValue('sAMAccountName')]
                elif member.hasAttribute('objectClass','group') and recursive:
                    members += self.resolveMembers(member, recursive)
        return members

    def formatAsGetent(self,entry):
        out = []
        out += [entry.getSingleValue('sAMAccountName')]
        out += ['*']
        out += [entry.getSingleValue('gidNumber')]
        members = self.resolveMembers(entry)
        members = ",".join(members)
        if 'memberUid' in entry:
            members += " ("+",".join(entry.values('memberUid'))+")"
        out += [members]
        return ":".join([x if x is not None else "" for x in out])

    def do_getent(self):
        accounts = self.search('(objectClass=posixGroup)')
        for entry in accounts:
            self.result(self.formatAsGetent(entry))

    def do_show(self):
        if len(self.args) > 0:
            accounts = self.args
        else: accounts = None
        if accounts is None and self.opts.gid is not None:
            entries = self.search('(&(objectClass=posixGroup)(gidNumber=%s))' % self.opts.gid)
            accounts = []
            for record in entries:
                if 'sAMAccountName' in record:
                    accounts += record['sAMAccountName']
        if accounts is None:
            self.error("No group specified to show")
            return
        for group in accounts:
            entries = self.search('(&(sAMAccountName=%s)(objectClass=group))' % group)
            if len(entries) < 1:
                self.result("No matching groups for %s" % group)
            elif len(entries) > 1:
                self.result("Error: %d matching groups for %s" % (len(entries),group))
            else:
                entry = entries[0]
                if not entry.hasAttribute('objectClass', 'posixGroup'):
                    self.result("%s: %s [no POSIX extensions]" % (group, ",".join(self.resolveMembers(entry))))
                else:
                    self.result(self.formatAsGetent(entry))
                    if 'userPassword' in entry or 'unixUserPassword' in entry:
                        self.result("#%s has unix password entries set!" % group)
