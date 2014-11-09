'''
Created on 28.10.2014

@author: mgr
'''

import ldap, ldap.sasl
import getpass

from SambaPosixLib.Logger import Logger

class LDAPQuery(object):
    def __init__(self, oConf, user = None):
        self.noTLS = oConf.noTLS
        self.URL = oConf.URI
        self.Base = oConf.Base
        self.Root = oConf.Root

        # No bind yet, we flag it as anonymous
        self.LDAP = None
        self.Anonymous = True

        # Optional stuff
        if isinstance(user, str):
            self.user = user
        else:
            self.user = None
        self.Logger = Logger()

        # do not perform modifications
        self.Dry = False

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

    def _search(self, base, query, privileged = False):
        if not self.connect(privileged):
            return None
        try:
            self.Logger.trace("Filter LDAP: %s" % query)
            results = self.LDAP.search_s(base, ldap.SCOPE_SUBTREE, query)
            # a list of tuples(DN, dict(item: [values as strings]))
        except ldap.LDAPError, error:
            log = Logger()
            log.error(error)
            return None
        return results

    def search(self, query, privileged = False):
        return self._search(self.Base, query, privileged)

    def searchRoot(self, path, query, privileged = False):
        path = path.strip()
        if len(path) > 0 and path[-1] != ',':
            path += ','
        return self._search(path + self.Root, query, privileged)

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

    def setDry(self, flag = True):
        if flag is True:
            self.Dry = True
        elif flag is False:
            self.Dry = False
        else:
            raise TypeError("Dry run flag is not boolean!")

    def modify(self,dn,modlist):
        if self.Dry:
            self.Logger.ldif("dn: %s" % dn)
            self.Logger.ldif("changetype: modify")
            for m in modlist:
                if m[0] == ldap.MOD_ADD:
                    self.Logger.ldif("add: %s" % m[1])
                elif m[0] == ldap.MOD_DELETE:
                    self.Logger.ldif("delete: %s" % m[1])
                elif m[0] == ldap.MOD_REPLACE:
                    self.Logger.ldif("replace: %s" % m[1])
                else:
                    raise ValueError("Unknown action for changetype modify!")
                if m[0] != ldap.MOD_DELETE or m[2] is not None:
                    self.Logger.ldif("%s: %s" % (m[1],m[2]))
                self.Logger.ldif('-')
        else:
            self.LDAP.modify_s(dn, modlist)

