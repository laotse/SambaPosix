'''
Created on 28.10.2014

@author: mgr
'''

import ldap, ldap.sasl
import getpass
import base64,re,struct

from SambaPosixLib.Logger import Logger

class LDAPQuery(object):
    def __init__(self, oConf, user = None):
        self.noTLS = oConf.noTLS
        self.URL = oConf.URI
        self.Base = oConf.Base

        # No bind yet, we flag it as anonymous
        self.LDAP = None
        self.Anonymous = True

        # Optional stuff
        if isinstance(user, str):
            self.user = user
        else:
            self.user = None
        self.Logger = Logger()

    def _bindAnonymous(self):
        log = Logger()
        try:
            self.LDAP = ldap.initialize(self.URL)
            if not self.noTLS:
                self.LDAP.start_tls_s()
            self.LDAP.simple_bind_s()
        except ldap.LDAPError, e:
            self.LDAP = None
            self.Anonymous = True
            log.error(e)
            return False
        self.Anonymous = True
        log.info("Anonymous bind to %s successful" % self.URL)
        return True

    def _bindSimple(self,user):
        log = Logger()
        # TODO: pre-query LDAP for DN is simple user name is given
        # TODO: more intelligently determine base for users
        dn = "CN=%s,%s" % (user,self.Base)
        pwd = getpass.getpass("Password for %s: " % user)
        try:
            self.LDAP = ldap.initialize(self.URL)
            if not self.noTLS:
                self.LDAP.start_tls_s()
            self.LDAP.simple_bind_s(dn,pwd)
        except ldap.LDAPError, e:
            self.LDAP = None
            self.Anonymous = True
            log.error("Could not authenticate to AD -- did you do a kinit?\n" + str(e))
            return False
        self.Anonymous = False
        log = Logger()
        log.debug("Simple bind as %s to %s successful" % (dn, self.URL))
        return True

    def _krbBind(self):
        log = Logger()
        try:
            auth = ldap.sasl.gssapi("")
            self.LDAP = ldap.initialize(self.URL)
            # SASL:[GSSAPI]: Sign or Seal are not allowed if TLS is used
            #adLDAP.start_tls_s()
            self.LDAP.sasl_interactive_bind_s("",auth)
        except ldap.LOCAL_ERROR, e:
            self.LDAP = None
            self.Anonymous = True
            log.error(e)
            return False
        self.Anonymous = False
        log.debug("Kerberos bind to %s successful" % self.URL)
        return True

    def connect(self, privileged = False):
        if self.LDAP is not None:
            if not privileged or not self.Anonymous:
                return True
        if not privileged:
            return self._bindAnonymous()
        if self.user is not None:
            return self._bindSimple(self.user)
        # Use Kerberos as default bind
        return self._krbBind()

    def search(self, query, privileged = False):
        if not self.connect(privileged):
            return None
        try:
            results = self.LDAP.search_s(self.Base, ldap.SCOPE_SUBTREE, query)
            # a list of tuples(DN, dict(item: [values as strings]))
        except ldap.LDAPError, error:
            log = Logger()
            log.error(error)
            return None
        return results

    def readDN(self, dn, privileged = False):
        if not self.connect(privileged):
            return None

        self.Logger.trace("Read entry %s" % (dn))
        results = self.LDAP.search_s(dn, ldap.SCOPE_BASE)
        if len(results) > 1:
            raise IndexError("Reading DN %s yielded %d results" % (dn, len(results)))
        if len(results) < 1:
            return None
        return results[0]

    def modify(self,dn,modlist):
        if self.opts.dry_run:
            self.Logger.ldif("dn: %s" % dn)
            self.Logger.ldif("changetype: modify")
            first = True
            for m in modlist:
                if not first:
                    self.Logger.ldif('-')
                if m[0] == ldap.MOD_ADD:
                    self.Logger.ldif("add: %s" % m[1])
                elif m[0] == ldap.MOD_DELETE:
                    self.Logger.ldif("delete: %s" % m[1])
                elif m[0] == ldap.MOD_REPLACE:
                    self.Logger.ldif("replace: %s" % m[1])
                else:
                    raise ValueError("Unknown action for changetype modify!")
                self.Logger.ldif("%s: %s" % (m[1],m[2]))
                first = False
        else:
            self.LDAP.modify_s(dn, modlist)

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

    def getDomainSID(self, sid = None, rid=None, raw = False):
        if sid is None:
            sid = self.readDN("CN=Administrator,"+self.Base, True)
            if sid is None:
                raise ValueError("Cannot find Administrator account in LDAP")
            sid = sid[1]['objectSid'][0]
        if not isinstance(sid, str) and hasattr(sid, '__contains__'):
            if 'objectSid' in sid: sid = sid['objectSid']
        if sid is not None and not isinstance(sid, str):
            print sid
            raise TypeError("Cannot convert %s to SID" % str(type(sid)))
        if not re.match('^S(?:-[0-9]{1,10}){3,7}$', sid):
            # this is a binary representation
            sid = self.decodeSID(sid)
        domainSID = "-".join(sid.split('-')[:-1])
        if not rid is None:
            if isinstance(rid, (int,long)):
                rid = "%d" % rid
            if not re.match("^[0-9]{1,10}$", rid):
                raise ValueError("RID %s is invalid" % str(rid))
            domainSID += "-%s" % rid
        return self.encodeSID(domainSID, raw)

