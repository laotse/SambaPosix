'''
Created on 28.10.2014

A singleton meta-class

For Python2 use:
@code
class MyClass(object):
    __metaclass__ = Singleton
@endcode

For Python3 use:
@code
class MyClass(metaclass=Singleton):
    pass
@endcode

This meta-class is explained in http://stackoverflow.com/questions/6760685/creating-a-singleton-in-python

@author: mgr
'''

class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args,**kwargs)
        return cls._instances[cls]
