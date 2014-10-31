'''
Created on 30.10.2014

@author: mgr
'''
from optparse import OptionGroup

import ldap

from SambaPosixLib.PosixValidator import PosixValidator as Validator

from SambaPosixLib.Command import Command, InvalidCommand
from SambaPosixLib.Group import Group

class ManageGroups(Command):
    '''
    classdocs
    '''
    Command = "group"

    def __init__(self,args,opts,oLDAP):
        '''
        Constructor
        '''
        self._setupUsage("group", False)
        Command.__init__(self, args, opts, oLDAP)

    @classmethod
    def optionGroup(cls, parser):
        # FIXME: we have -g,--gid for users as well
        group = OptionGroup(parser,"Options for Posix groups")
        #group.add_option("-g", "--gid", dest="gid", help="set numerical group ID", metavar="GID")
        parser.add_option_group(group)
        return parser

    def usage(self, msg):
        indent = " " * 3
        out = msg + "\n\n"
        out += self.Usage + "\n"
        out += indent + "getent [group] - getent for one or all POSIX groups" + "\n"
        out += indent + "set [group] [--gid GID] - make existing group a POSIX group and assign GID\n"
        out += indent + "help - this help page"
        return out

    def do_getent(self):
        if len(self.args) > 1:
            group = Group.byName(self.args[1], self.LDAP)
            if group is False:
                self.Logger.error("Group %s does not exist!" % self.args[1])
                return 1
            print group.formatAsGetent()
            return 0
        for group in Group.posixGroups(self.LDAP):
            print group.formatAsGetent(self.LDAP)
        return 0

    def do_set(self):
        if self.opts.gid is not None and not Validator.checkPOSIXID(self.opts.gid):
            self.Logger.error("%s is an invalid group ID" % self.opts.gid)
            return 5
        if len(self.args) < 2:
            if self.opts.gid is not None:
                group = Group.byGID(self.opts.gid, self.LDAP)
            else:
                raise InvalidCommand("group set requires a group name or a gid")
        else:
            group = Group.byName(self.args[1], self.LDAP)
        if group is None:
            self.error("Group %s specified for modification does not exist" % self.args[1])
            return 1

        modify = []
        if not group.hasAttribute('objectClass', 'posixGroup'):
            modify += [(ldap.MOD_ADD, 'objectClass', 'posixGroup')]
        gid = group.getSingleValue('gidNumber')
        if gid is None:
            if self.opts.gid is None:
                raise InvalidCommand("group set %s -- no gid assigned nor specified" % self.args[1])

            modify += [(ldap.MOD_ADD, 'gidNumber', self.opts.gid)]
        elif gid != self.opts.gid:
            modify += [(ldap.MOD_REPLACE, 'gidNumber', self.opts.gid)]

        if len(modify) > 0:
            self.LDAP.modify(group.dn(), modify)

        return 0

    def do_run(self):
        if len(self.args) < 1:
            raise InvalidCommand("group requires sub-commands")
        if self.args[0] == "getent":
            return self.do_getent()
        if self.args[0] == "set":
            return self.do_set()
        if self.args[0] == "help":
            self.print_usage("user help", False)
            return 0
        raise InvalidCommand("group %s unknown" % self.args[0])