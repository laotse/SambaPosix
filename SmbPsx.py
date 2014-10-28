'''
Created on 28.10.2014

@author: mgr
'''

from SambaPosixLib.LDAPQuery import LDAPQuery
from SambaPosixLib.LDAPConf import LDAPConf

import sys,pprint,os

if __name__ == '__main__':
    LC = LDAPConf()
    if os.path.isfile('/etc/ldap/ldap.conf'):
        LC.parseConf('/etc/ldap/ldap.conf')
        LC.extendBase("CN=Users,")
    # Kerberos bind
    LQ = LDAPQuery(LC)
    # simple bind
    #LQ = LDAPQuery("ldap://samba.ad.microsult.de","CN=Users,DC=ad,DC=microsult,DC=de", False, "Administrator")
    results = LQ.search("(&(objectClass=user)(sAMAccountName=mgr))", True)
    if results is None:
        sys.exit()

    pp = pprint.PrettyPrinter()
    pp.pprint(results)