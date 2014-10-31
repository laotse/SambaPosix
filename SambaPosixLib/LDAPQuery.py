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
        log.info("Simple bind as %s to %s successful" % (dn, self.URL))
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
        log.info("Kerberos bind to %s successful" % self.URL)
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
