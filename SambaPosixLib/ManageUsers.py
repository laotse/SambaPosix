'''
Created on 29.10.2014

@author: mgr
'''

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
        #group = OptionGroup(parser,"Options for Posix user accounts")
        modparsers = modparse.add_subparsers(dest="command")
        set_parser = modparsers.add_parser('set', help='set POSIX attributes to user')
        set_parser.add_argument("user", help="user to modify")
        set_parser.add_argument("-u", "--uid", dest="uid", help="set / use numerical user ID", metavar="UID")
        set_parser.add_argument("--user", dest="user", help="choose user name", metavar="NAME")
        set_parser.add_argument("-g", "--gid", dest="gid", help="set numerical group ID of login group", metavar="GID")
        set_parser.add_argument("-G", "--group", dest="group", help="set group name of login group", metavar="NAME")
        set_parser.add_argument("--gecos", dest="gecos", help="set gecos", metavar="NAME")
        set_parser.add_argument("--shell", dest="shell", help="set shell", metavar="PATH")
        set_parser.add_argument("--home", dest="home", help="set home directory", metavar="PATH")

        id_parser = modparsers.add_parser('id', help='get id like output for one or more users')
        id_parser.add_argument("user", nargs='+', help="user to show")

        get_parser = modparsers.add_parser("getent", help="get getent like output for one, more, or all POSIX users")
        get_parser.add_argument("user", nargs='*', help="user to list")
        #parser.add_option_group(group)
        return True

    def usage(self, msg):
        indent = " " * 3
        out = msg + "\n\n"
        out += self.Usage + "\n"
        out += indent + "getent [user] - getent for one or all POSIX users" + "\n"
        out += indent + "id user [...] - get id like entries for one or more users"
        out += indent + "help - this help page"
        return out

    def do_getent(self):
        if len(self.opts['user']) > 0:
            for name in self.opts['user']:
                user = User.byAccount(name, self.LDAP)
                if user is False:
                    log = Logger()
                    log.error("User %s does not exist!" % name)
                    return 1
                print user.formatAsGetent()
            return 0
        for user in User.posixUsers(self.LDAP):
            print user.formatAsGetent()
        return 0

    def do_id(self):
        log = Logger()
        for name in self.opts['user']:
            user = User.byAccount(name, self.LDAP)
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

    def do_run(self):
        if self.command == "getent":
            return self.do_getent()
        if self.command == "id":
            return self.do_id()
        raise InvalidCommand("user %s unknown" % self.command)

