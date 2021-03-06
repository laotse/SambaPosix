'''
Created on 30.10.2014

@author: mgr
'''

import ldap

from SambaPosixLib.Logger import Logger
from SambaPosixLib.PosixValidator import PosixValidator as Validator

from SambaPosixLib.Command import Command, InvalidCommand
from SambaPosixLib.Group import Group
from SambaPosixLib.User import User
from SambaPosixLib.NisDomain import NisDomain

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

        get_parser = modparsers.add_parser("getent", help="get getent like output for one, more, or all POSIX groups")
        get_parser.add_argument("group", nargs='*', help="group to list")
        get_parser.add_argument('-P', '--include-primary-group', action='store_true', dest="primaries", help="also list users as members, which have the group as primary group")

        add_parser = modparsers.add_parser("add", help="add users to group")
        add_parser.add_argument("group", help="group to add users to")
        add_parser.add_argument("users", nargs="+", help="users to add")

        rem_parser = modparsers.add_parser("rem", help="remove users from group")
        rem_parser.add_argument("group", help="group to remove users from")
        rem_parser.add_argument("users", nargs="+", help="users to remove")

        unposix_parser = modparsers.add_parser("unposix", help="remove POSIX attributes from groups")
        unposix_parser.add_argument("--unposix-all-groups", action="store_true", dest="all", help="confirm complete removal of POSIX settings from all groups - only if no groups are specified!")
        unposix_parser.add_argument("group", nargs='*', help="groups to remove POSIX attributes from")

        fix_parser = modparsers.add_parser("fix", help="make POSIX attributes consistent and adhere to chosen profile")
        fix_parser.add_argument("--fix-all-groups", action="store_true", dest="all", help="confirm fixing all groups with POSIX touch - only if no groups are specified!")
        fix_parser.add_argument("group", nargs='*', help="groups to fix POSIX attributes")

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
                primaryUsers = []
                if self.opts['primaries'] is True:
                    rid = group.getRID()
                    for user in User.filterUsers(self.LDAP, '(&(objectClass=user)(uidNumber=*)(primaryGroupID=%d))' % rid):
                        primaryUsers += [user.getName()]
                print group.formatAsGetent(self.LDAP, primaryUsers)
            return 0
        for group in Group.posixGroups(self.LDAP):
            print group.formatAsGetent(self.LDAP)
        return 0

    def _unposix(self, group):
        modify = []
        if group.hasAttribute('gidNumber'):
            modify += [(ldap.MOD_DELETE, 'gidNumber', None)]
        if group.hasAttribute('objectClass', 'posixGroup'):
            modify += [(ldap.MOD_DELETE, 'objectClass', 'posixGroup')]

        if len(modify) > 0:
            self.LDAP.modify(group.dn(), modify)

    def do_unposix(self):
        if len(self.opts['group']) == 0:
            if not self.opts['all'] is True:
                self.Logger.error("You must either specify a list of groups to remove POSIX from, or supply --unposix-all-groups")
                return 5
            for group in Group.posixGroups(self.LDAP):
                self._unposix(group)
        else:
            for name in self.opts['group']:
                group = self._byName(name)
                if group is False:
                    log = Logger()
                    log.error("Group %s does not exist!" % name)
                    return 1
                self._unposix(group)
        return 0

    def _fix(self, group):
        modify = []
        try:
            gid = group.getSingleValue('gidNumber')
        except IndexError:
            gid = None
        if gid is None:
            self._unposix(group)
            return

        NIS = NisDomain()
        if group.hasAttribute('objectClass', 'posixGroup') and not NIS.objectClass():
            modify += [(ldap.MOD_DELETE, 'objectClass', 'posixGroup')]
        elif not group.hasAttribute('objectClass', 'posixGroup') and NIS.objectClass():
            modify += [(ldap.MOD_ADD, 'objectClass', 'posixGroup')]

        # TODO: check memberOf of members - more complex than for users due to group nesting

        modify = [x for x in modify if not x is None]
        if len(modify) > 0:
            self.LDAP.modify(group.dn(), modify)

    def do_fix(self):
        if len(self.opts['group']) == 0:
            if not self.opts['all'] is True:
                self.Logger.error("You must either specify a list of groups to fix POSIX, or supply --fix-all-groups")
                return 5
            NIS = NisDomain()
            if NIS.msRFU():
                max_gid = 0
                for group in Group.filterGroups(self.LDAP, '(&(objectClass=group)(|(gidNumber=*)(objectClass=posixGroup)))'):
                    self._fix(group)
                    if group.hasAttribute('uidNumber'):
                        gid = group.getSingleValue('gidNumber')
                        if gid > max_gid: max_gid = gid
                if max_gid > 0:
                    NIS.storeGID(max_gid, self.LDAP)
        else:
            for name in self.opts['group']:
                group = self._byName(name)
                if group is False:
                    log = Logger()
                    log.error("Group %s does not exist!" % name)
                    return 1
                self._fix(group)
        return 0

    def do_set(self):
        group = self._byName(self.opts['group'])
        if group is False:
            self.Logger.error("Group %s specified for modification does not exist" % self.opts['group'])
            return 1

        modify = []
        if self.opts['gid'] is not None and not Validator.checkPosixID(self.opts['gid']):
            self.Logger.error("%s is an invalid group ID" % self.opts['gid'])
            return 5

        NIS = NisDomain()
        if not group.hasAttribute('objectClass', 'posixGroup') and NIS.objectClass():
            modify += [(ldap.MOD_ADD, 'objectClass', 'posixGroup')]
        elif group.hasAttribute('objectClass', 'posixGroup') and not NIS.objectClass():
            modify += [(ldap.MOD_DELETE, 'objectClass', 'posixGroup')]

        gid = group.getSingleValue('gidNumber')
        if gid is None:
            if self.opts['gid'] is None:
                if NIS.msRFU():
                    uid, ngid = NIS.nextID(self.LDAP)
                else: ngid = False
                if ngid is False:
                    raise InvalidCommand("group set %s -- no gid assigned nor specified" % self.opts['group'])
                self.opts['gid'] = ngid

            modify += [(ldap.MOD_ADD, 'gidNumber', self.opts['gid'])]
        elif gid != self.opts['gid']:
            modify += [(ldap.MOD_REPLACE, 'gidNumber', self.opts['gid'])]
            if NIS.msRFU():
                NIS.storeGID(self.opts['gid'], self.LDAP)

        if len(modify) > 0:
            self.LDAP.modify(group.dn(), modify)

        return 0

    def do_add(self):
        group = self._byName(self.opts['group'])
        if group is False:
            self.Logger.error("Group %s specified for adding users does not exist" % self.opts['group'])
            return 1

        modify = []
        for user in self.opts['users']:
            if not Validator.checkPosixName(user):
                self.error("User name %s invalid -- skipped" % user)
                continue
            oUser = User.byAccount(user, self.LDAP)
            if oUser is None:
                self.Logger.error("Unknown user %s -- skipped" % user)
            else:
                pgRID = oUser.getSingleValue('primaryGroupID')
                if int(pgRID) == group.getRID():
                    self.Logger.info('User %s has group %s as primary group, i.e. is already a member' % (oUser.getName(),group.getSingleValue('sAMAccountName')))
                else:
                    if not group.hasAttribute('member', oUser.dn()):
                        modify += [(ldap.MOD_ADD, 'member', oUser.dn())]
                    else:
                        self.Logger.info('User %s is member of  %s, already' % (oUser.getName(),group.getSingleValue('sAMAccountName')))

                # 'linked attribute' maintained automatically by AD
                # if not oUser.hasAttribute('memberOf', group.dn()):
                #    self.LDAP.modify(oUser.dn(), [(ldap.MOD_ADD, 'memberOf', group.dn())])

        if len(modify) > 0:
            self.LDAP.modify(group.dn(), modify)

    def do_remove(self):
        # FIXME: If user has us as primaryGID, we cannot remove!
        group = self._byName(self.opts['group'])
        if group is False:
            self.Logger.error("Group %s specified for adding users does not exist" % self.opts['group'])
            return 1

        modify = []
        for user in self.opts['users']:
            if not Validator.checkPosixName(user):
                self.error("User name %s invalid -- skipped" % user)
                continue
            oUser = User.byAccount(user, self.LDAP)
            if oUser is None:
                self.error("Unknown user %s -- skipped" % user)
            else:
                primaryRID = oUser.getSingleValue('primaryGroupID')
                if int(primaryRID) == group.getRID():
                    self.Logger.info("User %s has %s as primary group -- cannot remove user" % (oUser.getName(), group.getSingleValue('sAMAccountName')))
                else:
                    if group.hasAttribute('member', oUser.dn()):
                        modify += [(ldap.MOD_DELETE, 'member', oUser.dn())]

                # memberOf is mainatained automatically by AD
                #if oUser.hasAttribute('memberOf', group.dn()):
                #    self.LDAP.modify(oUser.dn(), [(ldap.MOD_DELETE, 'memberOf', group.dn())])

        if len(modify) > 0:
            self.LDAP.modify(group.dn(), modify)


    def do_run(self):
        if self.command == "getent":
            return self.do_getent()
        if self.command == "set":
            return self.do_set()
        if self.command == "add":
            return self.do_add()
        if self.command == "rem":
            return self.do_remove()
        if self.command == "unposix":
            return self.do_unposix()
        if self.command == "fix":
            return self.do_fix()

        raise InvalidCommand("group %s unknown" % self.command)
