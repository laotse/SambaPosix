'''
Created on 28.10.2014

@author: mgr
'''

import re, urlparse
import ldap, ldap.dn

from SambaPosixLib.Logger import Logger

class LDAPConf(object):
    '''
    classdocs
    '''


    def __init__(self):
        '''
        Constructor
        '''
        self.URI = None
        self.Base = None
        self.noTLS = True

    def parseConf(self, fname):
        log = Logger()
        with open(fname, 'r') as f:
            log.debug("Opened %s for reading" % fname)
            for line in f:
                if re.match('^\s*(?:#.*)?$',line): continue
                re.sub('\s*#.*$','',line)
                res = re.match('^\s*([A-Z_]+)\s+(.*)$',line)
                if res is False:
                    log.error("Invalid line in %s: %s" % (fname,line))
                else:
                    if res.group(1) == 'URI':
                        self.setURI(res.group(2))
                    elif res.group(1) == 'BASE':
                        self.Base = res.group(2)
                    elif res.group(1) == "TLS_CACERT":
                        self.noTLS = False

    def setTLS(self, tls):
        if tls is True:
            self.noTLS = False
        else:
            self.noTLS = True

    def setURI(self,uri):
        tURL = urlparse.urlparse(uri, "ldap", False)
        if not isinstance(tURL, tuple) or tURL[0] not in ['ldap','ldaps']:
            log = Logger()
            log.error("URL: %s invalid for LDAP" % uri)
            raise ValueError("Invalid LDAP URL: %s" % uri)
        self.URI = tURL.geturl()

    def setBase(self,base):
        try:
            if base  is None: base = ""
            if not base == "":
                ldap.dn.str2dn(base)
        except ldap.DECODING_ERROR:
            log = Logger()
            log.error("Search base: %s is invalid DN" % base)
            raise ValueError("Invalid base DN: %s" % base)

        self.Base = base

    def extendBase(self, rdn):
        self.setBase(rdn + self.Base)
