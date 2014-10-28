'''
Created on 28.10.2014

@author: mgr
'''
from SambaPosixLib.LDAPEntry import LDAPEntry
from SambaPosixLib.Logger import Logger

class User(LDAPEntry):
    '''
    classdocs
    '''


    def __init__(self,entry):
        '''
        Constructor
        '''
        LDAPEntry.__init__(self,entry)

    @classmethod
    def byAccount(cls, account, oLDAP):
        log = Logger()
        results = oLDAP.search('(&(objectClass=user)(sAMAccountName=%s))' % account, True)
        if results is None or len(results) < 1:
            log.debug("No user for account %s" % account)
            return False
        if len(results) > 1:
            log.error("AD database corrupt: %d entries for user account %s" % (len(results),account))
            return False

        return cls(results[0])
