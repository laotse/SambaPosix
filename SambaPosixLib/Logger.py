'''
Created on 28.10.2014

A simple logger available as Singleton for the entire program

Supports:
 - message prefixing
 - verbosity levels

Default logging to stderr

@author: mgr
'''
from SambaPosixLib.Singleton import Singleton
import sys

class Logger(object):
    __metaclass__ = Singleton

    def log(self, msg):
        if hasattr(self, 'fh') and self.fh is not None:
            self.fh.write(msg + '\n')
        else:
            sys.stderr.write(msg + '\n')

    def result(self, msg):
        if hasattr(self, 'fh') and self.fh is not None:
            self.fh.write(msg + '\n')
        sys.stdout.write(msg + "\n")

    def setVerbosity(self, level):
        self.Verbosity = level

    def setFile(self, name):
        try:
            self.fh.close()
        except:
            pass
        try:
            self.fh = open(name,'w')
        except IOError, e:
            self.fh = None
            self.error("Cannot open file %s for logging: %s" %(name,str(e)))
            return False
        return True

    def conditionalLog(self, msg, level):
        if not hasattr(self, 'Verbosity'):
            self.setVerbosity(0)
        if level > self.Verbosity:
            return
        return self.log(msg)

    def _prefixMsg(self, msg, pre):
        if not hasattr(msg, 'split') or not hasattr(msg.split, '__call__'):
            msg = str(msg)
        indent = " " * len(pre)
        out = pre
        aLines = msg.split('\n')
        out += aLines[0]
        if len(aLines) > 1:
            for i in range(1,len(aLines)):
                out += "\n"
                if len(aLines[i]) > 0:
                    out += indent + aLines[i]
        return out

    def error(self,msg):
        return self.log(self._prefixMsg(msg, "[Error] "))

    def trace(self,msg):
        return self.conditionalLog(self._prefixMsg(msg, "[Trace] "), 5)

    def debug(self,msg):
        return self.conditionalLog(self._prefixMsg(msg, "[Trace] "), 3)

    def warn(self,msg):
        return self.conditionalLog(self._prefixMsg(msg, "[Warn] "), 1)

    def info(self,msg):
        return self.conditionalLog(msg, 1)

