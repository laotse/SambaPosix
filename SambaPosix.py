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

import sys
import os

import ldap, ldap.sasl

from optparse import OptionParser, OptionGroup

__all__ = []
__version__ = 0.1
__date__ = '2014-09-11'
__updated__ = '2014-09-11'

DEBUG = 1
TESTRUN = 0
PROFILE = 0

def main(argv=None):
    '''Command line options.'''

    program_name = os.path.basename(sys.argv[0])
    program_version = "v0.1"
    program_build_date = "%s" % __updated__

    program_version_string = '%%prog %s (%s)' % (program_version, program_build_date)
    # program_usage = "usage: %s cmd [options]" % program_name
    program_longdesc = '''''' # optional - give further explanation about what the program does
    program_license = "Copyright 2014 Dr. Lars Hanke (µAC - Microsystem Accessory Consult)                                            \
                Licensed under the GNU Public License v3\nhttp://www.gnu.org/licenses/gpl-3.0.html"

    if argv is None:
        argv = sys.argv[1:]

    # setup option parser
    parser = OptionParser(version=program_version_string, epilog=program_longdesc, description=program_license)
    #parser.set_usage(program_usage)
    # set defaults
    parser.set_defaults(base="dc=ad,dc=microsult,dc=de", url="ldap://samba.ad.microsult.de")

    group = OptionGroup(parser,"General options")
    group.add_option("-v", "--verbose", dest="verbose", action="count", help="set verbosity level [default: %default]")
    group.add_option("-n", "--dry", dest="dry_run", help="do not modify LDAP, just show what would be done")
    group.add_option("-o", "--log", dest="logfile", help="set logfile path and enable logging", metavar="FILE")
    group.add_option("", "--show", dest="show", help="show information present in LDAP")
    group.add_option("-H", "--url", dest="url", help="URL of AD DC [default: %default]", metavar="URL")
    group.add_option("-b", "--base", dest="base", help="Base DN [default: %default]", metavar="DN")
    parser.add_option_group(group)

    cmd = None
    doArgs = True
    for arg in argv:
        if not doArgs:
            cmd = arg
            break
        if arg[0] != '-':
            cmd = arg
            break
        if arg == '--':
            doArgs = False

    if cmd is None:
        sys.stderr.write(program_name + " command [options]" + "\n")
        indent = len(program_name) * " "
        sys.stderr.write(indent + "  for help use --help")
        return 2

    if cmd == 'user':
        from SambaPosix.User import User
        User(argv, parser, program_name)

        """
        if opts.verbose > 0:
            print("verbosity level = %d" % opts.verbose)
        if opts.infile:
            print("infile = %s" % opts.infile)
        if opts.outfile:
            print("outfile = %s" % opts.outfile)
        """


if __name__ == "__main__":
    if DEBUG:
        #sys.argv.append("-h")
        pass
    if TESTRUN:
        import doctest
        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = '_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit(main())