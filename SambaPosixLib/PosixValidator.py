'''
Created on 30.10.2014

@author: mgr
'''

import re, string

class PosixValidator(object):
    '''
    classdocs
    '''

    @classmethod
    def checkPOSIXID(cls,val):
        if val is None: return True
        if not re.match('^[0-9]+$',val): return False
        if int(val) > 65535: return False
        return True

    @classmethod
    def checkPosixName(cls,val):
        if val is None: return True
        # FIXME: should be NAME_REGEX
        if not re.match('^[_.A-Za-z0-9][-\@_.A-Za-z0-9]*\$?$',val): return False
        # FIXME: should be LOGIN_NAME_MAX
        if len(val) > 255: return False
        return True

    @classmethod
    def checkPosixPath(cls,val):
        if val is None: return True
        # must be absolute
        if not val[0] == '/': return False
        # find non-printables
        if not all(c in string.printable for c in val):
            return False
        # this would break getent
        if re.search(':',val):
            return False
        # FIXME: should be PATH_MAX
        if len(val) > 1024: return False
        return True

    @classmethod
    def checkGecos(cls,val):
        if val is None: return True
        # find non-printables
        if not all(c in string.printable for c in val):
            return False
        # this would break getent
        if re.search(':',val):
            return False
        # FIXME: no idea what may be a good length
        if len(val) > 1024: return False
        return True
