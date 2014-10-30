'''
Created on 30.10.2014

@author: mgr
'''
from optparse import OptionGroup

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

    def do_run(self):
        if len(self.args) < 1:
            raise InvalidCommand("group requires sub-commands")
        if self.args[0] == "getent":
            return self.do_getent()
        if self.args[0] == "help":
            self.print_usage("user help", False)
            return 0
        raise InvalidCommand("group %s unknown" % self.args[0])