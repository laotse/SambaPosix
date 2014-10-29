'''
Created on 29.10.2014

@author: mgr
'''
from optparse import OptionGroup

from SambaPosixLib.Command import Command
from SambaPosixLib.User import User

class ManageUsers(Command):
    '''
    classdocs
    '''

    def __init__(self,args,opts,oLDAP):
        Command.__init__(self, args, opts, oLDAP)
        self.command = "user"

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

    def do_run(self):
        user = User.byAccount('mac', self.LDAP)
        if not user is False:
            print user.formatAsGetent()
        return 0
