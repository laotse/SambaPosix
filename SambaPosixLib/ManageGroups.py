'''
Created on 30.10.2014

@author: mgr
'''

import ldap

from SambaPosixLib.PosixValidator import PosixValidator as Validator

from SambaPosixLib.Command import Command, InvalidCommand
from SambaPosixLib.Group import Group

class ManageGroups(Command):
    '''
    classdocs
    '''
    Command = "group"

    def __init__(self,opts,oLDAP):
        '''
        Constructor
        '''
        self._setupUsage("group", False)
        Command.__init__(self, opts, oLDAP)
        self.command = opts['command']

    @classmethod
    def optionGroup(cls, subparsers):
        modparse = subparsers.add_parser('group', help='group management')
        modparsers = modparse.add_subparsers(dest="command")
        set_parser = modparsers.add_parser('set', help='set POSIX attributes to group')
        set_parser.add_argument("group", help="group to modify")
        set_parser.add_argument("-g", "--gid", dest="gid", help="set numerical group ID", metavar="GID")

        get_parser = modparsers.add_parser("getent", help="get getent like output for one, more, or all POSIX groups")
        get_parser.add_argument("group", nargs='*', help="group to list")

        return True

    def usage(self, msg):
        indent = " " * 3
        out = msg + "\n\n"
        out += self.Usage + "\n"
        out += indent + "getent [group] - getent for one or all POSIX groups" + "\n"
        out += indent + "set [group] [--gid GID] - make existing group a POSIX group and assign GID\n"
        out += indent + "help - this help page"
        return out

    def do_getent(self):
        if len(self.opts['group']) > 1:
            for name in self.opts['group']:
                group = Group.byName(name, self.LDAP)
                if group is False:
                    self.Logger.error("Group %s does not exist!" % name)
                    return 1
                print group.formatAsGetent()
            return 0
        for group in Group.posixGroups(self.LDAP):
            print group.formatAsGetent(self.LDAP)
        return 0

    def do_set(self):
        if self.opts['gid'] is not None and not Validator.checkPOSIXID(self.opts['gid']):
            self.Logger.error("%s is an invalid group ID" % self.opts['gid'])
            return 5

        group = Group.byName(self.opts['group'], self.LDAP)
        if group is None:
            self.error("Group %s specified for modification does not exist" % self.opts['group'])
            return 1

        modify = []
        if not group.hasAttribute('objectClass', 'posixGroup'):
            modify += [(ldap.MOD_ADD, 'objectClass', 'posixGroup')]
        gid = group.getSingleValue('gidNumber')
        if gid is None:
            if self.opts['gid'] is None:
                raise InvalidCommand("group set %s -- no gid assigned nor specified" % self.opts['group'])

            modify += [(ldap.MOD_ADD, 'gidNumber', self.opts['group'])]
        elif gid != self.opts['group']:
            modify += [(ldap.MOD_REPLACE, 'gidNumber', self.opts['group'])]

        if len(modify) > 0:
            self.LDAP.modify(group.dn(), modify)

        return 0

    def do_run(self):
        if self.command == "getent":
            return self.do_getent()
        if self.command == "set":
            return self.do_set()

        raise InvalidCommand("group %s unknown" % self.command)
