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

"""
If you really want your script to be of use, convert these bash script excerpts to python:

# Finds the next useable user uidNumber or group gidNumber
# Input : $1
# $1 : msSFU30MaxUidNumber or msSFU30MaxGidNumber
# Output : the first free uidNumber or gidNumber
_findnext () {
  _NEXTID=$($LDBSEARCHBIN -H $DBPATH -b "CN=$LDOMAIN,CN=ypservers,CN=ypServ30,CN=RpcServices,CN=System,$SUFFIX" -s sub '(objectClass=msSFU30DomainInfo)' $1 | grep "$1: " | awk '{print $NF}')
  if [ -z "$_NEXTID" ] || [ "$_NEXTID" -lt "$IDSTART" ]; then
    _NEXTID="$IDSTART"
  fi
}

# UPDATE msSFU30MaxUidNumber/msSFU30MaxGidNumber
# Input : $1 $2
# $1: what to update (msSFU30MaxUidNumber or msSFU30MaxGidNumber)
# $2: Next Number
#
# Output : Nothing
_updatemax () {
log_output "Updating $1"

echo "dn: CN=$LDOMAIN,CN=ypservers,CN=ypServ30,CN=RpcServices,CN=System,$SUFFIX
changetype: modify
replace: $1
$1: $2" > /tmp/newgid

$LDBMODIFYBIN --url=$KERBEROS /tmp/newgid  2>>"$LOGFILE" 1>/dev/null
if [ $? != 0 ]; then
    log_output "Error updating $1 in AD."
    exit 1 # exits here if error
fi
rm -f /tmp/newgid
log_output "Successfully updated $1 in AD"
}
"""
