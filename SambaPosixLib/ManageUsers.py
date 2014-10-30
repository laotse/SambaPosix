'''
Created on 29.10.2014

@author: mgr
'''
from optparse import OptionGroup

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

    def __init__(self,args,opts,oLDAP):
        self._setupUsage("user", False)
        Command.__init__(self, args, opts, oLDAP)

    @classmethod
    def optionGroup(cls, parser):
        group = OptionGroup(parser,"Options for Posix user accounts")
        group.add_option("-u", "--uid", dest="uid", help="set numerical user ID", metavar="UID")
        group.add_option("", "--user", dest="user", help="choose user name", metavar="NAME")
        group.add_option("-g", "--gid", dest="gid", help="set numerical group ID of login group", metavar="GID")
        group.add_option("-G", "--group", dest="group", help="set group name of login group", metavar="NAME")
        group.add_option("", "--gecos", dest="gecos", help="set gecos", metavar="NAME")
        group.add_option("", "--shell", dest="shell", help="set shell", metavar="PATH")
        group.add_option("", "--home", dest="home", help="set home directory", metavar="PATH")
        parser.add_option_group(group)
        return parser

    def usage(self, msg):
        indent = " " * 3
        out = msg + "\n\n"
        out += self.Usage + "\n"
        out += indent + "getent [user] - getent for one or all POSIX users" + "\n"
        out += indent + "id user [...] - get id like entries for one or more users"
        out += indent + "help - this help page"
        return out

    def do_getent(self):
        if len(self.args) > 1:
            user = User.byAccount(self.args[1], self.LDAP)
            if user is False:
                log = Logger()
                log.error("User %s does not exist!" % self.args[1])
                return 1
            print user.formatAsGetent()
            return 0
        for user in User.posixUsers(self.LDAP):
            print user.formatAsGetent()
        return 0

    def do_id(self):
        log = Logger()
        if len(self.args) < 2:
            raise InvalidCommand("user id requires a user name")
        for name in self.args[1:]:
            user = User.byAccount(name, self.LDAP)
            if user is False:
                log.error("User %s does not exist!" % self.args[1])
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
        if len(self.args) < 1:
            raise InvalidCommand("user requires sub-commands")
        if self.args[0] == "getent":
            return self.do_getent()
        if self.args[0] == "id":
            return self.do_id()
        if self.args[0] == "help":
            self.print_usage("user help", False)
            return 0
        raise InvalidCommand("user %s unknown" % self.args[0])

