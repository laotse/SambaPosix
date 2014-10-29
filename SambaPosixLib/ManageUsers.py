'''
Created on 29.10.2014

@author: mgr
'''

from SambaPosixLib.Command import Command
from SambaPosixLib.User import User

class ManageUsers(Command):
    '''
    classdocs
    '''

    def do_run(self):
        user = User.byAccount('mac', self.LDAP)
        if not user is False:
            print user.formatAsGetent()
        return 0
