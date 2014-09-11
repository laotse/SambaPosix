'''
Created on 11.09.2014

@author: mgr
'''

from SambaPosix.Command import Command
from optparse import OptionGroup

import ldap

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

    def sanitizeOptions(self):
        if not self.checkPOSIXID(self.opts.gid):
            raise ValueError("%s is not valid for group id" % self.opts.gid)
        return Command.sanitizeOptions(self)

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

    def locateByGID(self,gid):
        entries = self.search('(&(objectClass=posixGroup)(gidNumber=%s))' % self.opts.gid)
        accounts = []
        for record in entries:
            if 'sAMAccountName' in record:
                accounts += record['sAMAccountName']
        return accounts

    def locateFirstGroup(self):
        group = None
        if len(self.args) > 0:
            group = self.args[0]
            if not self.checkPosixName(group):
                raise ValueError("Group name %s invalid" % group)
            entries = self.search('(&(sAMAccountName=%s)(objectClass=group))' % group)
            if len(entries) > 1:
                self.result("Error: %d matching groups for %s" % (len(entries),group))
            if len(entries) == 1:
                self.args = self.args[1:]
                return group,entries[0]

        if self.opts.gid is not None:
            entries = self.search('(&(objectClass=posixGroup)(gidNumber=%s)(objectClass=group))' % self.opts.gid)
            if len(entries) > 1:
                self.result("Error: %d matching groups for %s" % (len(entries),self.opts.gid))
            if len(entries) == 1:
                return entries[0].getSingleValue('sAMAccountName'), entries[0]

        return None, None

    def locateUser(self, name):
        entries = self.search('(&(sAMAccountName=%s)(objectClass=user))' % name)
        if len(entries) > 1:
            self.error("Error: %d matching users for %s" % (len(entries),name))
            return None
        if len(entries) < 1:
            return None
        return entries[0].dn()

    def do_show(self):
        if len(self.args) > 0:
            accounts = self.args
        else: accounts = None
        if accounts is None and self.opts.gid is not None:
            accounts = self.locateByGID(self.opts.gid)
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

    def do_set(self):
        group, entry = self.locateFirstGroup()
        if group is None:
            self.error("No group specified for modification")
            return

        modify = []
        if not entry.hasAttribute('objectClass', 'posixGroup'):
            modify += [(ldap.MOD_ADD, 'objectClass', 'posixGroup')]
        gid = entry.getSingleValue('gidNumber')
        if gid is None:
            modify += [(ldap.MOD_ADD, 'gidNumber', self.opts.gid)]
        elif gid != self.opts.gid:
            modify += [(ldap.MOD_REPLACE, 'gidNumber', self.opts.gid)]

        if len(modify) > 0:
            self.modify(entry.dn(), modify)

    def do_add(self):
        group, entry = self.locateFirstGroup()
        if group is None:
            self.error("No group specified for adding users")
            return

        modify = []
        for user in self.args:
            if not self.checkPosixName(user):
                self.error("User name %s invalid -- skipped" % user)
                continue
            dn = self.locateUser(user)
            if dn is None:
                self.error("Unknown user %s -- skipped" % user)
            else:
                if not entry.hasAttribute('member', dn):
                    modify += [(ldap.MOD_ADD, 'member', dn)]

            if len(modify) > 0:
                # FIXME: raises ldap.ALREADY_EXISTS on the second user - adding single users works fine
                self.modify(entry.dn(), modify)


