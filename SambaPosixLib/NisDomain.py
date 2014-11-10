'''
Created on 09.11.2014

@author: mgr
'''

import re, base64, struct
import ldap.dn

from SambaPosixLib.Singleton import Singleton
from SambaPosixLib.LDAPEntry import LDAPEntry
from SambaPosixLib.Logger import Logger

class NisDomain(object):
    __metaclass__ = Singleton
    '''
    classdocs
    '''

    def __init__(self):
        '''
        Constructor
        '''
        # initialize database scheme to hybrid
        self.do_msRFU = True
        self.do_objectClasses = True
        # some domain value caches
        self.domainSID = None
        self.nisDomain = None
        # UID and GID start values
        # TODO: read them from some config file and options
        self.uidStart = 10000
        self.gidStart = 10000

    ##
    # LDAP support for M$ proprietary NIS fields
    #
    # Get / set support for M$ fields:
    # - msSFU30Name
    # - msSFU30NisDomain
    # - unixUserPassword
    #
    # This also enables reading / updating
    # parameters to the M$ NIS implementation
    # in AD.
    #
    # If flag is given, support will be set or
    # unset. If omitted, the state will only be
    # queried.
    #
    # @param flag: bool, True for M$ support
    # @return bool
    def msRFU(self, flag = None):
        if flag is True:
            self.do_msRFU = True
        elif flag is False:
            self.do_msRFU = False
        return self.do_msRFU

    ##
    # LDAP support for POSIX objectClass
    #
    # Get / set support for POSIX objectClass
    # - posixAccount
    # - posixGroup
    #
    #
    # If flag is given, support will be set or
    # unset. If omitted, the state will only be
    # queried.
    #
    # @param flag: bool, True for objectClass support
    # @return bool
    def objectClass(self, flag = None):
        if flag is True:
            self.do_objectClasses = True
        elif flag is False:
            self.do_objectClasses = False
        return self.do_objectClasses

    ##
    # Set database options according to schema
    #
    # - ldap: use objectClasses and support only fields supported by those
    # - aduc: simulate M$ ADUC entries
    # - hybrid: ADUC + objectClasses
    #
    # @param schema: str name of scheme
    # @return: bool
    def setSchema(self,schema):
        if schema == 'ldap':
            self.msRFU(False)
            self.objectClass(True)
        elif schema == 'aduc':
            self.msRFU(True)
            self.objectClass(False)
        elif schema == 'hybrid':
            self.msRFU(True)
            self.objectClass(True)
        else:
            return False
        return True

    @classmethod
    def decodeSID(cls, val):
        def decode(v):
            o = 0L
            for i in range(len(v)):
                o <<= 8
                o |= v[i]
            return "-%d" % o

        if re.match('^[A-Za-z0-9+/]+={0,2}$',val):
            try:
                bVal = base64.b64decode(val)
            except TypeError:
                # this is probably a binary already
                bVal = val
        else:
            bVal = val

        if isinstance(bVal, str):
            bVal = [ord(x) for x in bVal]

        out = "S"
        out += decode([bVal[0]])
        groups = bVal[1]

        l = groups + 2
        l *= 4
        if l != len(bVal):
            #print "SID: " + str(bVal)
            raise ValueError("SID with %d groups should have length: %d, but %d bytes passed!" % (groups,l,len(bVal)))

        # this is big endian
        out += decode(bVal[2:8])

        # the rest is little endian
        for i in range(8,l,4):
            out += decode(list(reversed(bVal[i:i+4])))

        return out

    @classmethod
    def encodeSID(cls, s, raw = False):
        def encode(v, rev=True, pad=4):
            out = []
            v = int(v)
            while v > 0:
                out += [v & 0xff]
                v >>= 8
            while len(out) < pad:
                out += [0]
            if not rev:
                out.reverse()
            if len(out) != pad or v != 0:
                raise ValueError("Error encoding SID - illegal component value")
            return out

        components = s.split("-")
        if components[0] != "S":
            raise ValueError("SID must start with 'S'")
        if len(components) < 3:
            raise ValueError("SID must contain at least 3 parts")
        for p in components[1:]:
            if not re.match('^[0-9]+$',p):
                raise ValueError("SID parts must be numerical")
        groups = len(components)-3

        sid = [int(components[1]),groups]
        sid += encode(components[2],False,6)
        for p in components[3:]:
            sid += encode(p)

        sid = struct.pack('B'* len(sid), *sid)
        if raw: return sid
        return base64.b64encode(sid)

    def getDomainSID(self, oLDAP, sid = None, rid=None, raw = False):
        if self.domainSID is None:
            # self.Base is "CN=Users," + BASE (see oConfig.extendBase("CN=Users,") in SamabaPosxi.py)
            domainBase = ldap.dn.dn2str(ldap.dn.str2dn(self.Base)[1:])
            domain = oLDAP.readDN(domainBase, True)
            if domain is not None and 'objectSid' in domain[1]:
                sid = domain[1]['objectSid'][0]
            else:
                raise ValueError("Domain entry has no objectSID")
            self.domainSID = self.decodeSID(sid)

        domainSID = self.domainSID
        if not rid is None:
            if isinstance(rid, (int,long)):
                rid = "%d" % rid
            if not re.match("^[0-9]{1,10}$", rid):
                raise ValueError("RID %s is invalid" % str(rid))
            domainSID += "-%s" % rid
        return self.encodeSID(domainSID, raw)

    def getNisDomain(self, oLDAP):
        if self.nisDomain is not None:
            return self.nisDomain

        log = Logger()
        if isinstance(oLDAP, str):
            self.nisDomain = oLDAP.lower()
            log.trace("NIS domain set to: %s" % self.nisDomain)
            return True

        results = oLDAP.searchRoot('CN=ypservers,CN=ypServ30,CN=RpcServices,CN=System,','(msSFU30Domains=*)', True)
        if results is None:
            self.nisDomain = None
            return False
        domains = dict()
        for entry in results:
            info = LDAPEntry(entry)
            for domain in info.values('msSFU30Domains'):
                domains[domain] = True
        domains = domains.keys()
        if len(domains) < 1:
            self.nisDomain = None
            return False
        if len(domains) > 1:
            log.error("Multiple domains unsupported - choose on of %s for -W option" % " ,".join(domains))
            return False
        self.nisDomain = domains[0]
        log.trace("NIS domain set to: %s" % self.nisDomain)
        return True

    def _getDomainYP(self, oLDAP):
        domain = self.getNisDomain(oLDAP)
        if domain is False:
            return False

        entry = oLDAP.readDN("CN=%s,%s" % (domain,"CN=ypservers,CN=ypServ30,CN=RpcServices,CN=System," + oLDAP.Root), True)
        if entry is None:
            return False
        return LDAPEntry(entry)

    def nextID(self, oLDAP):
        entry = self._getDomainYP(oLDAP)
        if entry is False:
            return (False, False)

        if entry.hasAttribute('msSFU30MaxUidNumber'):
            uid = entry.getSingleValue('msSFU30MaxUidNumber')
            uid = int(uid) + 1
        else:
            uid = self.uidStart
        if entry.hasAttribute('msSFU30MaxGidNumber'):
            gid = entry.getSingleValue('msSFU30MaxGidNumber')
            gid = int(gid) +  1
        else:
            gid = self.gidStart

        return (uid,gid)

    def _storeID(self, guid, att, oLDAP):
        entry = self._getDomainYP(oLDAP)
        if entry is False:
            return False

        if entry.hasAttribute(att):
            val = entry.getSingleValue(att)
            if int(val) != int(guid):
                oLDAP.modify(entry.dn(),[(ldap.MOD_REPLACE,att,guid)])
        else:
            oLDAP.modify(entry.dn(),[(ldap.MOD_ADD,att,guid)])

        return True

    def storeUID(self, uid, oLDAP):
        return self._storeID(uid, 'msSFU30MaxUidNumber', oLDAP)

    def storeGID(self, gid, oLDAP):
        return self._storeID(gid, 'msSFU30MaxGidNumber', oLDAP)
