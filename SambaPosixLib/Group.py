'''
Created on 30.10.2014

@author: mgr
'''
from SambaPosixLib.LDAPEntry import LDAPEntry
from SambaPosixLib.Logger import Logger
from SambaPosixLib.PosixValidator import PosixValidator as Validator

class Group(LDAPEntry):
    '''
    classdocs
    '''


    def __init__(self,entry):
        '''
        Constructor
        '''
        LDAPEntry.__init__(self,entry)

    @classmethod
    def byName(cls, name, oLDAP):
        log = Logger()
        if not Validator.checkPosixName(name):
            log.error("%s is no valid POSIX group name" % name)
            return False
        results = oLDAP.search('(&(objectClass=group)(sAMAccountName=%s))' % name, True)
        if results is None or len(results) < 1:
            log.debug("No group called %s" % name)
            return False
        if len(results) > 1:
            log.error("AD database corrupt: %d entries for group name %s" % (len(results),name))
            return False

        return cls(results[0])

    @classmethod
    def byGID(cls, gid, oLDAP):
        log = Logger()
        if not Validator.checkPOSIXID(gid):
            log.error("%s is no valid POSIX GID" % gid)
            return False
        entries = oLDAP.search('(&(objectClass=posixGroup)(gidNumber=%s))' % gid)
        if len(entries) > 1:
            accounts = []
            for record in entries:
                if 'sAMAccountName' in record:
                    accounts += record['sAMAccountName']
                else:
                    accounts += record.dn()
            log.error("%s all share gid %s" % (", ".join(accounts), gid))
            return False
        return cls(entries[0])

    @classmethod
    def byMemberDN(cls, dn, oLDAP):
        entries = oLDAP.search('(&(objectClass=group)(member=%s))' % dn)
        for group in entries:
            yield cls(group)
