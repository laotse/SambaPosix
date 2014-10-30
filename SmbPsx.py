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
from SambaPosixLib.Command import InvalidCommand

import sys,os
from optparse import OptionParser, OptionGroup

__all__ = []
__version__ = 0.1
__date__ = '2014-09-11'
__updated__ = '2014-10-28'

def main(argv = None):
    '''Command line options.'''

    program_name = os.path.basename(sys.argv[0])
    program_version = "v0.1"
    program_build_date = "%s" % __updated__

    program_version_string = '%%prog %s (%s)' % (program_version, program_build_date)
    program_usage = "usage: %s cmd [options]" % program_name
    program_longdesc = '''''' # optional - give further explanation about what the program does
    program_license = "Copyright 2014 Dr. Lars Hanke (µAC - Microsystem Accessory Consult)                                            \
                Licensed under the GNU Public License v3\nhttp://www.gnu.org/licenses/gpl-3.0.html".decode('utf8')

    program_modules = [ManageUsers]

    if argv is None:
        argv = sys.argv[1:]

    # setup option parser
    parser = OptionParser(version=program_version_string, epilog=program_longdesc, description=program_license)
    parser.set_usage(program_usage)
    # set defaults
    oConfig = LDAPConf()
    if os.path.isfile('/etc/ldap/ldap.conf'):
        oConfig.parseConf('/etc/ldap/ldap.conf')
        oConfig.extendBase("CN=Users,")

    parser.set_defaults(base=oConfig.Base, url=oConfig.URI, dry_run=False, verbose=0, bind_user=None)

    group = OptionGroup(parser,"General options")
    group.add_option("-v", "--verbose", dest="verbose", action="count", help="set verbosity level [default: %default]")
    group.add_option("-n", "--dry", dest="dry_run", action="store_true", help="do not modify LDAP, just show what would be done")
    group.add_option("-o", "--log", dest="logfile", help="set logfile path and enable logging", metavar="FILE")
    group.add_option("-H", "--url", dest="url", help="URL of AD DC [default: %default]", metavar="URL")
    group.add_option("-b", "--base", dest="base", help="Base DN [default: %default]", metavar="DN")
    group.add_option("-U", "--bind-user", dest="bind_user", help="User for simple bind", metavar="CN | uid")
    group.add_option("", "--no-tls", dest="noTLS", action="store_true", help="Don't use TLS for simple bind")
    parser.add_option_group(group)

    for module in program_modules:
        parser = module.optionGroup(parser)

    (opts, args) = parser.parse_args(argv)
    oConfig.setBase(opts.base)
    oConfig.setURI(opts.url)
    oConfig.setTLS(not opts.noTLS)
    log = Logger()
    if opts.logfile is not None:
        log.setFile(opts.logfile)
    log.setVerbosity(opts.verbose)

    if isinstance(opts.bind_user, str):
        oLDAP = LDAPQuery(oConfig, opts.bind_user)
    else:
        oLDAP = LDAPQuery(oConfig)

    if len(args) <= 0:
        parser.error('missing command, try "help"')
        return 5
    try:
        if args[0] == 'help':
            parser.error("supported commands: user help")
            return 0
        for module in program_modules:
            if args[0] == module.Command:
                return module.run(args,opts,oLDAP)

        parser.error("Unknown command: %s" % args[0])
        return 5
    except InvalidCommand, e:
        print str(e)
        return 5

if __name__ == '__main__':
    sys.exit(main())
