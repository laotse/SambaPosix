#!/usr/bin/env python
# encoding: utf-8
'''
 -- shortdesc

Toolsuite to manage POSIX users in an AD

@author:     Dr. Lars Hanke

@copyright:  2014 µAC - Microsystem Accessory Consult. All rights reserved.

@license:    GPLv3

@contact:    debian@lhanke.de
@deffield    updated: Updated
'''
from SambaPosixLib.Logger import Logger

from SambaPosixLib.LDAPQuery import LDAPQuery
from SambaPosixLib.LDAPConf import LDAPConf

from SambaPosixLib.ManageUsers import ManageUsers
from SambaPosixLib.ManageGroups import ManageGroups
from SambaPosixLib.Toolbox import Toolbox
from SambaPosixLib.Command import InvalidCommand

import sys,os,re,socket
import argparse
from urlparse import urlparse
from SambaPosixLib.NisDomain import NisDomain

__all__ = []
__version__ = 0.2
__date__ = '2014-09-11'
__updated__ = '2014-11-05'

def main(argv = None):
    '''Command line options.'''

    program_name = os.path.basename(sys.argv[0])
    program_version = "v0.1"
    program_build_date = "%s" % __updated__

    program_version_string = '%%prog %s (%s)' % (program_version, program_build_date)
    #program_usage = "usage: %s cmd [options]" % program_name
    program_longdesc = '''''' # optional - give further explanation about what the program does
    program_license = "Copyright 2014 Dr. Lars Hanke (µAC - Microsystem Accessory Consult)                                            \
                Licensed under the GNU Public License v3\nhttp://www.gnu.org/licenses/gpl-3.0.html".decode('utf8')

    program_modules = [ManageUsers,ManageGroups, Toolbox]

    if argv is None:
        argv = sys.argv[1:]

    # setup option parser
    parser = argparse.ArgumentParser(epilog=program_longdesc, description=program_version_string + '\n'+ program_license)
    #parser.set_usage(program_usage)
    # set defaults
    oConfig = LDAPConf()
    if os.path.isfile('/etc/ldap/ldap.conf'):
        oConfig.parseConf('/etc/ldap/ldap.conf')
        oConfig.extendBase("CN=Users,")

    # FIXME: should be a NETLOGON, but nothing seems to support CLDAP
    # however https://github.com/geertj/python-ad/blob/master/lib/ad/protocol/netlogon.py might help
    #parsed_url = urlparse(oConfig.URI, 'ldap')
    #fqdn = socket.getfqdn(re.sub(':\d+$','',parsed_url[1]))
    #domain = fqdn.split('.')[1]

    parser.set_defaults(base=oConfig.Base,
                        url=oConfig.URI,
                        dry_run=False,
                        verbose=0,
                        bind_user=None,
                        workgroup=None,
                        schema=os.getenv('SAMBA_POSIX_SCHEME',"hybrid"))

    parser.add_argument("-V", "--version", action='version', version=program_version_string)
    group = parser.add_argument_group("General options")
    group.add_argument("-v", "--verbose", dest="verbose", action="count", help="set verbosity level [default: %(default)i]")
    group.add_argument("-n", "--dry", dest="dry_run", action="store_true", help="do not modify LDAP, just show what would be done")
    group.add_argument("-o", "--log", dest="logfile", help="set logfile path and enable logging", metavar="FILE")
    group.add_argument("-H", "--url", dest="url", help="URL of AD DC [default: %(default)s]", metavar="URL")
    group.add_argument("-b", "--base", dest="base", help="Base DN [default: %(default)s]", metavar="DN")
    group.add_argument("-U", "--bind-user", dest="bind_user", help="User for simple bind", metavar="CN | uid")
    group.add_argument("--no-tls", dest="noTLS", action="store_true", help="Don't use TLS for simple bind")
    group.add_argument("-W", "--workgroup", dest="workgroup", help="NETBIOS name of AD", metavar="WORKGROUP")
    schema = parser.add_mutually_exclusive_group()
    schema.add_argument("--rfc2307", dest="schema", action="store_const", const="ldap", help="use LDAP schema compliant POSIX entries")
    schema.add_argument("--ADUC", dest="schema", action="store_const", const="aduc", help="simulate entries created by ADUC")
    schema.add_argument("--hybrid", dest="schema", action="store_const", const="hybrid", help="use ADUC fields and POSIX object classes")
    #parser.add_option_group(group)
    module_parsers = parser.add_subparsers(help='sub-command help', dest="module")

    for module in program_modules:
        module.optionGroup(module_parsers)

    opts = vars(parser.parse_args())
    oConfig.setBase(opts['base'])
    oConfig.setURI(opts['url'])
    oConfig.setTLS(not opts['noTLS'])
    log = Logger()
    if opts['logfile'] is not None:
        log.setFile(opts['logfile'])
    log.setVerbosity(opts['verbose'])

    if isinstance(opts['bind_user'], str):
        oLDAP = LDAPQuery(oConfig, opts['bind_user'])
    else:
        oLDAP = LDAPQuery(oConfig)

    if opts['dry_run'] is True:
        oLDAP.setDry()

    NIS = NisDomain()
    if not NIS.setSchema(opts['schema']):
        log.error("Unknown database schema: %s" % opts['schema'])
        return 5

    if opts['workgroup'] is None and NIS.msRFU():
        if not NIS.getNisDomain(oLDAP):
            log.error("Cannot determine NIS domain")
            return 5
    elif opts['workgroup'] is not None:
        NIS.getNisDomain(opts['workgroup'])

    try:
        for module in program_modules:
            if opts['module'] == module.Command:
                return module.run(opts,oLDAP)

        parser.error("Unknown command: %s" % opts['module'])
        return 5
    except InvalidCommand, e:
        print str(e)
        return 5

if __name__ == '__main__':
    sys.exit(main())
