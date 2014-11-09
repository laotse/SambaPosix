'''
Created on 28.10.2014

@author: mgr
'''
import ldap.dn, base64

from SambaPosixLib.LDAPQuery import LDAPQuery
from SambaPosixLib.LDAPEntry import LDAPEntry
from SambaPosixLib.Logger import Logger
from SambaPosixLib.PosixValidator import PosixValidator as Validator, ADValidator
from SambaPosixLib.NisDomain import NisDomain

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
        if not Validator.checkPosixName(account):
            log.error("%s is no valid POSIX user name")
            return False
        results = oLDAP.search('(&(objectClass=user)(sAMAccountName=%s))' % account, True)
        if results is None or len(results) < 1:
            log.debug("No user for account %s" % account)
            return False
        if len(results) > 1:
            log.error("AD database corrupt: %d entries for user account %s" % (len(results),account))
            return False

        return cls(results[0])

    @classmethod
    def byUID(cls, uid, oLDAP):
        log = Logger()
        if not Validator.checkPosixID(uid):
            log.error("%s is no valid POSIX user id")
            return False
        NIS = NisDomain()
        if NIS.objectClass():
            results = oLDAP.search('(&(objectClass=posixAccount)(objectClass=user)(uidNumber=%s))' % uid, True)
        else:
            results = oLDAP.search('(&(objectClass=user)(uidNumber=%s))' % uid, True)
        if results is None or len(results) < 1:
            log.debug("No user for uid %s" % uid)
            return False
        if len(results) > 1:
            log.error("POSIX settings corrupt: %d entries for user id %s" % (len(results),uid))
            return False

        return cls(results[0])

    @classmethod
    def bySID(cls, sid, oLDAP):
        log = Logger()
        rid = ADValidator.normalizeRID(sid)
        if not rid is False and isinstance(rid, int):
            # this is a RID
            sid = oLDAP.getDomainSID(None, rid, True)
        else:
            if ADValidator.checkSID(sid):
                # this is a plain SID
                sid = oLDAP.encodeSID(sid,True)
            elif ADValidator.checkBase64(sid):
                # this could be a base64 encoded SID
                sid = base64.b64decode(sid)
            # else: binary SID, do nothing!
        esid = ldap.filter.escape_filter_chars(sid,2)
        entries = oLDAP.search('(&(objectClass=user)(objectSid=%s))' % esid)
        if entries is not None and len(entries) > 1:
            log.error("AD database corrupt: %d entries for user SID %s" % (len(entries),oLDAP.decodeSID(sid)))
            return False
        if entries is None or len(entries) < 1:
            log.trace("User SID %s not found!" % oLDAP.decodeSID(sid))
            return False
        return cls(entries[0])

    @classmethod
    def posixUsers(cls,oLDAP):
        NIS = NisDomain()
        if NIS.objectClass():
            results = oLDAP.search('(&(objectClass=posixAccount)(objectClass=user))', True)
        else:
            results = oLDAP.search('(&(objectClass=user)(uidNumber=*))', True)

        for result in results:
            yield cls(result)

    @classmethod
    def filterUsers(cls,oLDAP, filt = '(&(objectClass=user)(uidNumber=*))'):
        results = oLDAP.search(filt, True)
        for result in results:
            yield cls(result)

    @classmethod
    def byDN(cls, dn, oLDAP):
        try:
            ldap.dn.str2dn(dn)
        except ldap.DECODING_ERROR:
            # this is not a valid DN, so we accept it as user name
            dn = ldap.dn.escape_dn_chars(dn)
            dn = "CN=" + dn + "," + oLDAP.Base
        result = oLDAP.readDN(dn, True)
        if result is None:
            log = Logger()
            log.trace("No entries found for DN: %s" % dn)
            return False

        return cls(result)

    def formatAsGetent(self):
        out = []
        out += [self.getSingleValue('uid')]
        out += ['x']
        out += [self.getSingleValue('uidNumber')]
        out += [self.getSingleValue('gidNumber')]
        out += [self.getSingleValue('gecos')]
        out += [self.getSingleValue('unixHomeDirectory')]
        out += [self.getSingleValue('loginShell')]

        return ":".join([x if x is not None else "" for x in out])

    def getSID(self):
        sid = self.getSingleValue('objectSid')
        return LDAPQuery.decodeSID(sid)

    def formatAsSID(self):
        values = []
        values += [self.getSingleValue('uid')]
        values += [self.getSingleValue('sAMAccountName')]
        values += [self.getSingleValue('uidNumber')]
        values += [self.getSID()]
        values = [x if isinstance(x, str) else "*" for x in values]
        out = values[1]
        if values[0] != values[1]:
            out += " [!%s]" % values[0]
        out += ":%s:" % values[2]
        out += values[3]
        return out

    def getName(self):
        name = self.getSingleValue('uid')
        if name is None or not isinstance(name, str):
            name = self.getSingleValue('sAMAccountName')
        return name
