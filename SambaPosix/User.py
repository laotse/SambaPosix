'''
Created on 11.09.2014

@author: mgr
'''

from SambaPosix.Command import Command
from optparse import OptionGroup

import ldap

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

    def sanitizeOptions(self):
        if not self.checkPOSIXID(self.opts.uid):
            raise ValueError("%s is not valid for user id" % self.opts.uid)
        if not self.checkPOSIXID(self.opts.gid):
            raise ValueError("%s is not valid for group id" % self.opts.gid)
        if not self.checkPosixName(self.opts.user):
            raise ValueError("%s is not valid for user name" % self.opts.user)
        if not self.checkPosixName(self.opts.group):
            raise ValueError("%s is not valid for group name" % self.opts.group)
        if not self.checkPosixPath(self.opts.shell):
            raise ValueError("%s is not valid for shell" % self.opts.shell)
        if not self.checkPosixPath(self.opts.home):
            raise ValueError("%s is not valid for home" % self.opts.home)
        if not self.checkGecos(self.opts.gecos):
            raise ValueError("%s is not valid for gecos" % self.opts.gecos)
        return Command.sanitizeOptions(self)

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

    def locateFirstUser(self):
        user = None
        if len(self.args) > 0:
            user = self.args[0]
            if not self.checkPosixName(user):
                raise ValueError("User name %s invalid" % user)
            entries = self.search('(&(sAMAccountName=%s)(objectClass=user))' % user)
            if len(entries) > 1:
                self.result("Error: %d matching users for %s" % (len(entries),user))
            if len(entries) == 1:
                self.args = self.args[1:]
                return user,entries[0]

        if self.opts.uid is not None:
            entries = self.search('(&(objectClass=posixAccount)(uidNumber=%s)(objectClass=user))' % self.opts.uid)
            if len(entries) > 1:
                self.result("Error: %d matching users for %s" % (len(entries),self.opts.uid))
            if len(entries) == 1:
                return entries[0].getSingleValue('sAMAccountName'), entries[0]

        return None, None

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

    def locateGroupByGID(self,gid):
        if not self.checkPOSIXID(gid):
            return None
        entries = self.search('(&(objectClass=group)(objectClass=posixGroup)(gidNumber=%s))' % gid)
        if len(entries) < 1:
            return None
        if len(entries) == 1:
            return entries[0]
        self.error("There are multiple groups for gid: %s" % gid)
        return None

    def do_id(self):
        user, entry = self.locateFirstUser()
        if user is None:
            self.error("No user specified!")
            return

        uid = entry.getSingleValue('uidNumber')
        if uid is None: uid = '*'
        out = "uid=%s(%s)" % (uid,user)
        gid = entry.getSingleValue('primaryGroupID')
        if gid is None:
            out += " gid=*"
        else:
            group = self.locateGroupByGID(gid)
            if group is None:
                out += " gid=%s(*)" % gid
            else:
                gname = group.getSingleValue('sAMAccountName')
                out += " gid=%s(%s)" % (gid,gname)

        # TODO: posixGroup !?
        entries = self.search('(&(objectClass=group)(member=%s))' % entry.dn())
        groups = []
        for group in entries:
            gid = group.getSingleValue('gidNumber')
            name = group.getSingleValue('sAMAccountName')
            if gid is None: gid = '*'
            groups += ["%s(%s)" % (gid,name)]
        if len(groups) > 0:
            out += " Groups=" + ",".join(groups)

        self.result(out)

    def makeModify(self,entry,val,attribute):
        if val is None:
            return None
        cur = entry.getSingleValue(attribute)
        if cur == val:
            return None
        if cur is None:
            return (ldap.MOD_ADD, attribute, val)
        return (ldap.MOD_REPLACE, attribute, val)

    def do_set(self):
        user, entry = self.locateFirstUser()
        if user is None:
            self.error("No user specified for modification")
            return

        modify = []
        if not entry.hasAttribute('objectClass', 'posixAccount'):
            modify += [(ldap.MOD_ADD, 'objectClass', 'posixAccount')]
        modify += [self.makeModify(entry, user, 'uid')]

        modify += [self.makeModify(entry, self.opts.uid, 'uidNumber')]
        modify += [self.makeModify(entry, self.opts.gid, 'primaryGroupID')]
        modify += [self.makeModify(entry, self.opts.home, 'unixHomeDirectory')]
        modify += [self.makeModify(entry, self.opts.shell, 'loginShell')]
        modify += [self.makeModify(entry, self.opts.gecos, 'gecos')]

        modify = [x for x in modify if not x is None]
        if len(modify) > 0:
            self.modify(entry.dn(), modify)
