'''
Created on 29.10.2014

@author: mgr
'''
import ldap

from SambaPosixLib.Logger import Logger
from SambaPosixLib.Command import Command, InvalidCommand
from SambaPosixLib.User import User
from SambaPosixLib.Group import Group
from SambaPosixLib.PosixValidator import PosixValidator as Validator

class ManageUsers(Command):
    '''
    classdocs
    '''
    Command = "user"

    def __init__(self,opts,oLDAP):
        self._setupUsage("user", False)
        Command.__init__(self, opts, oLDAP)
        self.command = opts['command']

    @classmethod
    def optionGroup(cls, subparsers):
        modparse = subparsers.add_parser('user', help='user management')
        source_id = modparse.add_mutually_exclusive_group()
        source_id.add_argument('-R','--by-RID',dest='byRID',action='store_true', help="reference users by SID / RID instead by user name")
        source_id.add_argument('--by-UID',dest='byGID',action='store_true', help="reference users by UID instead by user name")
        modparsers = modparse.add_subparsers(dest="command")
        set_parser = modparsers.add_parser('set', help='set POSIX attributes to user')
        set_parser.add_argument("user", help="user to modify")
        set_parser.add_argument("-u", "--uid", dest="uid", help="set / use numerical user ID", metavar="UID")
        set_parser.add_argument("--user", dest="user", help="choose user name", metavar="NAME")
        set_parser.add_argument("-g", "--gid", dest="gid", help="set group ID of login group - may be passed as numerical ID or as name of a POSIX group", metavar="GID")
        set_parser.add_argument("--gecos", dest="gecos", help="set gecos", metavar="NAME")
        set_parser.add_argument("--shell", dest="shell", help="set shell", metavar="PATH")
        set_parser.add_argument("--home", dest="home", help="set home directory", metavar="PATH")

        id_parser = modparsers.add_parser('id', help='get id like output for one or more users')
        id_parser.add_argument("user", nargs='+', help="user to show")

        get_parser = modparsers.add_parser("getent", help="get getent like output for one, more, or all POSIX users")
        get_parser.add_argument("user", nargs='*', help="user to list")

        sid_parser = modparsers.add_parser("sid", help="get SID of users")
        sid_parser.add_argument("user", nargs='*', help="user to retrieve SID")
        return True

    def _byName(self, name):
        if self.opts['byGID'] is True:
            return User.byUID(name, self.LDAP)
        if self.opts['byRID'] is True:
            return User.bySID(name, self.LDAP)
        return User.byAccount(name, self.LDAP)

    def do_getent(self):
        if len(self.opts['user']) > 0:
            for name in self.opts['user']:
                user = self._byName(name)
                if user is False:
                    log = Logger()
                    log.error("User %s does not exist!" % name)
                    return 1
                print user.formatAsGetent()
            return 0
        for user in User.posixUsers(self.LDAP):
            print user.formatAsGetent()
        return 0

    def do_sid(self):
        if len(self.opts['user']) > 0:
            for name in self.opts['user']:
                user = self._byName(name)
                if user is False:
                    log = Logger()
                    log.error("User %s does not exist!" % name)
                    return 1
                print user.formatAsSID()
            return 0
        for user in User.posixUsers(self.LDAP):
            print user.formatAsSID()
        return 0

    def do_id(self):
        log = Logger()
        for name in self.opts['user']:
            user = self._byName(name)
            if user is False:
                log.error("User %s does not exist!" % name)
                return 1

            uid = user.getSingleValue('uidNumber')
            if uid is None: uid = '*'
            uname = user.getSingleValue('sAMAccountName')
            if uname is None: uname = name
            out = "uid=%s(%s)" % (uid,uname)
            gid = user.getSingleValue('gidNumber')
            if gid is None:
                out += " gid=*"
            else:
                group = Group.byGID(gid, self.LDAP)
                if group is False:
                    out += " gid=%s(*)" % gid
                else:
                    gname = group.getSingleValue('sAMAccountName')
                    out += " gid=%s(%s)" % (gid,gname)

            grid = group.getRID()
            urid = user.getSingleValue('primaryGroupID')
            if not urid is None and int(grid) != int(urid):
                pgroup = Group.byRID(urid, self.LDAP, user.getSingleValue('objectSid'))
                if not pgroup is False:
                    out += "![%s]" % pgroup.getSingleValue('sAMAccountName')
                else:
                    out += "![*]"

            # TODO: posixGroup !?
            groups = []
            for group in Group.byMemberDN(user.dn(), self.LDAP):
                gid = group.getSingleValue('gidNumber')
                name = group.getSingleValue('sAMAccountName')
                if gid is None: gid = '*'
                groups += ["%s(%s)" % (gid,name)]
            if len(groups) > 0:
                out += " Groups=" + ",".join(groups)

            log.result(out)
        return 0

    def makeModify(self,entry,val,attribute, support = True):
        if not support:
            if not entry.hasAttribute(attribute):
                return None
            # delete all occurences, if it is unsupported
            return (ldap.MOD_DELETE, attribute, None)
        if val is None:
            return None
        cur = entry.getSingleValue(attribute)
        if cur == val:
            return None
        if cur is None:
            return (ldap.MOD_ADD, attribute, val)
        return (ldap.MOD_REPLACE, attribute, val)

    def do_set(self):
        # sanitize options
        try:
            if not Validator.checkPosixID(self.opts['uid']):
                raise ValueError("%s is not valid for user id" % self.opts['uid'])
            if not Validator.checkPosixID(self.opts['gid']):
                if Validator.checkPosixName(self.opts['gid']):
                    group = Group.byName(self.opts['gid'], self.LDAP)
                    if not group is None and group.hasAttribute('gidNumber'):
                        self.opts['gid'] = group.getSingleValue('gidNumber')
                    else:
                        raise ValueError("%s is not valid for group id" % self.opts['gid'])
                else:
                    raise ValueError("%s is not valid for group id" % self.opts['gid'])
            if not Validator.checkPosixName(self.opts['user']):
                raise ValueError("%s is not valid for user name" % self.opts['user'])
            if not Validator.checkPosixPath(self.opts['shell']):
                raise ValueError("%s is not valid for shell" % self.opts['shell'])
            if not Validator.checkPosixPath(self.opts['home']):
                raise ValueError("%s is not valid for home" % self.opts['home'])
            if not Validator.checkGecos(self.opts['gecos']):
                raise ValueError("%s is not valid for gecos" % self.opts['gecos'])
        except ValueError, e:
            self.Logger.error(str(e))
            return 5

        user = self._byName(self.opts['user'])
        if user is None:
            self.error("User %s not found in AD" % self.opts['user'])
            return 1

        name = user.getSingleValue('sAMAccountName')
        modify = []
        if not user.hasAttribute('objectClass', 'posixAccount') and self.LDAP.schema().objectClass():
            modify += [(ldap.MOD_ADD, 'objectClass', 'posixAccount')]
        elif user.hasAttribute('objectClass', 'posixAccount') and not self.LDAP.schema().objectClass():
            modify += [(ldap.MOD_DELETE, 'objectClass', 'posixAccount')]
        modify += [self.makeModify(user, name, 'uid')]
        modify += [self.makeModify(user, name, 'msSFU30Name', self.LDAP.schema().msRFU())]
        modify += [self.makeModify(user, self.LDAP.nis(), 'msSFU30NisDomain', self.LDAP.schema().msRFU())]

        modify += [self.makeModify(user, self.opts['uid'], 'uidNumber')]
        # TODO: auto-add user to group, if gid is given?

        gid = self.opts['gid']
        if gid is None: gid = user.getSingleValue('gidNumber')
        rid = user.getSingleValue('primaryGroupID')
        if gid is None:
            group = Group.byRID(rid, self.LDAP, user)
            if not group is None:
                gid = group.getSingleValue('gidNumber')
        modify += [self.makeModify(user, gid, 'gidNumber')]
        group = Group.byGID(gid, self.LDAP)
        if not group is None:
            modify += [self.makeModify(user, str(group.getRID()), 'primaryGroupID')]

        modify += [self.makeModify(user, self.opts['home'], 'unixHomeDirectory')]
        modify += [self.makeModify(user, self.opts['shell'], 'loginShell')]
        modify += [self.makeModify(user, self.opts['gecos'], 'gecos')]

        modify += [self.makeModify(user, 'ABCD!efgh12345$67890', 'unixUserPassword', self.LDAP.schema().msRFU())]

        modify = [x for x in modify if not x is None]
        if len(modify) > 0:
            self.LDAP.modify(user.dn(), modify)

    def do_run(self):
        if self.command == "getent":
            return self.do_getent()
        if self.command == "id":
            return self.do_id()
        if self.command == "sid":
            return self.do_sid()
        if self.command == "set":
            return self.do_set()
        raise InvalidCommand("user %s unknown" % self.command)

