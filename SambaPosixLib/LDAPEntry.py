'''
Created on 11.09.2014

@author: mgr
'''

from SambaPosixLib.Logger import Logger

class LDAPEntry(object):
    '''
    classdocs
    '''


    def __init__(self, entry):
        '''
        Constructor
        '''
        if isinstance(entry, str):
            # This is a DN only
            self.dn(entry)
            self.Attributes = []
        elif isinstance(entry, (tuple,list)) and len(entry) == 2:
            self.dn(entry[0])
            self.Attributes = entry[1]
        else:
            raise TypeError("Cannot construct %s from %s" % (self.__class__.__name__, str(type(entry))))

        # TODO: introduce some sanity checks here

    def __iter__(self):
        return self.Attributes.__iter__()

    def __contains__(self,item):
        if not item in self.Attributes:
            return False
        if len(self.Attributes[item]) < 1:
            return False
        return True

    def __getitem__(self,item):
        return self.Attributes[item]

    def __setitem__(self,item,value):
        return self.Attributes.__setitem__(item,value)

    def dn(self, val = None):
        if not val is None:
            # TODO: check if this is a valid DN
            self.DN = val
        return self.DN

    def removeAttribute(self,item):
        if item in self:
            del self.Attributes[item]

    def getSingleValue(self,item):
        if not item in self:
            return None
        if len(self.Attributes[item]) > 1:
            raise IndexError("Requested unique attribute %s of %s, but it exists %d times" % (item,self.dn(),len(self.Attributes[item])))
        return self.Attributes[item][0]

    def setSingleValue(self,item,value):
        self.Attributes[item] = [value]

    def values(self,item):
        if not item in self:
            raise StopIteration
        for value in self.Attributes[item]:
            yield value

    def addValue(self,item,value):
        if not item in self:
            self.setSingleValue(item, value)
        else:
            self.Attributes[item] += [value]

    def removeValue(self,item,value):
        if not item in self:
            return False
        if not value in self.Attributes[item]:
            return False
        del self.Attributes[item][value]
        return True

    def hasAttribute(self, item, value = None):
        if not item in self:
            return None
        if value is None:
            return True
        if value in self.Attributes[item]:
            return True
        return False

    def ldap(self):
        return (self.dn(), self.Attributes)

    def dump(self,level=3):
        import pprint
        log = Logger()
        log.conditionalLog("DN: " + self.dn(), level)
        log.conditionalLog(pprint.pformat(self.Attributes), level)

