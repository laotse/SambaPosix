'''
Created on 30.10.2014

@author: mgr
'''

import ldap

from SambaPosixLib.Logger import Logger
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
        source_id = modparse.add_mutually_exclusive_group()
        source_id.add_argument('-R','--by-RID',dest='byRID',action='store_true', help="reference groups by RID instead by group name")
        source_id.add_argument('-G','--by-GID',dest='byGID',action='store_true', help="reference groups by GID instead by group name")
        modparsers = modparse.add_subparsers(dest="command")
        set_parser = modparsers.add_parser('set', help='set POSIX attributes to group')
        set_parser.add_argument("group", help="group to modify")
        set_parser.add_argument("-g", "--gid", dest="gid", help="set numerical group ID", metavar="GID")
        set_parser.add_argument("--unposix", dest="unposix", action="store_true", help="remove POSIX attributes from group")

        get_parser = modparsers.add_parser("getent", help="get getent like output for one, more, or all POSIX groups")
        get_parser.add_argument("group", nargs='*', help="group to list")

        return True

    def _byName(self, name):
        if self.opts['byRID'] is True:
            return Group.byRID(name, self.LDAP)
        if  self.opts['byGID'] is True:
            return Group.byGID(name, self.LDAP)
        return Group.byName(name, self.LDAP)

    def do_getent(self):
        log = Logger()
        log.trace(str(self.opts))
        if len(self.opts['group']) > 0:
            for name in self.opts['group']:
                log.trace("Trying to locate group: %s" % name)
                group = self._byName(name)
                if group is False:
                    self.Logger.error("Group %s does not exist!" % name)
                    return 1
                print group.formatAsGetent(self.LDAP)
            return 0
        for group in Group.posixGroups(self.LDAP):
            print group.formatAsGetent(self.LDAP)
        return 0

    def do_set(self):
        group = self._byName(self.opts['group'])
        if group is False:
            self.Logger.error("Group %s specified for modification does not exist" % self.opts['group'])
            return 1

        modify = []
        if self.opts['unposix'] is True:
            if group.hasAttribute('gidNumber'):
                modify += [(ldap.MOD_DELETE, 'gidNumber', None)]
            if group.hasAttribute('objectClass', 'posixGroup'):
                modify += [(ldap.MOD_DELETE, 'objectClass', 'posixGroup')]
        else:
            if self.opts['gid'] is not None and not Validator.checkPosixID(self.opts['gid']):
                self.Logger.error("%s is an invalid group ID" % self.opts['gid'])
                return 5

            if not group.hasAttribute('objectClass', 'posixGroup'):
                modify += [(ldap.MOD_ADD, 'objectClass', 'posixGroup')]

            gid = group.getSingleValue('gidNumber')
            if gid is None:
                if self.opts['gid'] is None:
                    raise InvalidCommand("group set %s -- no gid assigned nor specified" % self.opts['group'])

                modify += [(ldap.MOD_ADD, 'gidNumber', self.opts['gid'])]
            elif gid != self.opts['gid']:
                modify += [(ldap.MOD_REPLACE, 'gidNumber', self.opts['gid'])]

        if len(modify) > 0:
            self.LDAP.modify(group.dn(), modify)

        return 0

    def do_run(self):
        if self.command == "getent":
            return self.do_getent()
        if self.command == "set":
            return self.do_set()

        raise InvalidCommand("group %s unknown" % self.command)
