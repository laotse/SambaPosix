'''
Created on 04.11.2014

@author: mgr
'''
import re, base64

from SambaPosixLib.Logger import Logger
from SambaPosixLib.Command import Command, InvalidCommand

class Toolbox(Command):
    '''
    classdocs
    '''
    Command = "tool"

    def __init__(self,opts,oLDAP):
        '''
        Constructor
        '''
        self._setupUsage("tool", False)
        Command.__init__(self, opts, oLDAP)
        self.command = opts['command']

    @classmethod
    def optionGroup(cls, subparsers):
        modparse = subparsers.add_parser('tool', help='various tools')
        modparsers = modparse.add_subparsers(dest="command")
        set_parser = modparsers.add_parser('sid', help='work with SID values')
        set_parser.add_argument("sid", help="SID value")
        set_parser.add_argument("-E", "--encode", dest="encode", action="store_true", help="convert text SID to base64")
        set_parser.add_argument("-D", "--decode", dest="decode", action="store_true", help="convert base64 to text SID")
        set_parser.add_argument("-R", "--escaped-raw", dest="raw", action="store_true", help="output as escaped instead of base64")

        return True

    def do_sid(self):
        log = Logger()
        raw = self.opts['raw']
        if self.opts['encode']:
            res = self.LDAP.encodeSID(self.opts['sid'], raw)
        elif self.opts['decode']:
            res = self.LDAP.decodeSID(self.opts['sid'])
        else:
            if re.match('^S(?:-[0-9]{1,10}){3,7}$', self.opts['sid']):
                res = self.LDAP.encodeSID(self.opts['sid'], raw)
            elif re.match('^[A-Za-z0-9+/]+={0,2}$',self.opts['sid']):
                if raw:
                    res = base64.b64decode(self.opts['sid'])
                else:
                    res = self.LDAP.decodeSID(self.opts['sid'])
            else:
                #doesn't match anything
                log.error("SID: %s doesn't appear in any known format. Please specify -E or -D")
                return 5
        if raw:
            res = "".join(['\%02x' % ord(x) for x in res])
        log.result(res)
        return 0


    def do_run(self):
        if self.command == "sid":
            return self.do_sid()

        raise InvalidCommand("group %s unknown" % self.command)