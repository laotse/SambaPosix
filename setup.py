#!/usr/bin/env python
from distutils.core import setup

setup(name="SambaPosix",
      version="0.2",
      description="Manage POSIX accounts in Samba4 AD",
      author="Dr. Lars Hanke",
      author_email="debian@lhanke.de",
      url="http://www.lhanke.de",
      packages = ['SambaPosixLib'],
      license = 'GPLv3',
      scripts = ['SambaPosix.py'],
      )
