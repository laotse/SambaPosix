'''
Created on 29.10.2014

@author: mgr
'''

class Command(object):
    '''
    classdocs
    '''


    def __init__(self,args,opts,oLDAP):
        '''
        Constructor
        '''
        self.args = args[1:]
        self.opts = opts
        self.LDAP = oLDAP
        self.command = None

    @classmethod
    def optionGroup(cls, parser):
        return parser

    @classmethod
    def run(cls,args,opts,oLDAP):
        oCls = cls(args,opts,oLDAP)
        return oCls.do_run()

    def do_run(self):
        raise NotImplementedError("Please implement the main handler for %s" % self.__class__.__name__)
