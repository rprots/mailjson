#!/usr/bin/env python

from distutils.core import setup
from .mailjson import __version__ as version

CLASSIFIERS = """\
Development Status :: 4 - Beta
Intended Audience :: Developers
Programming Language :: Python
Programming Language :: Python :: 2
Programming Language :: Python :: 3
Topic :: Software Development
Operating System :: POSIX
Operating System :: Unix
"""

setup(name='mailjson',
      version=version,
      description='Mail to JSON converter',
      author='vitush',
      author_email='vitush.dev@gmail.com',
      url='https://github.com/vitush/MailJson',
      license='MIT license',
      packages = ['mailjson'],
      long_description=open('README.md').read(),
      classifiers = [cl for cl in CLASSIFIERS.split('\n') if cl],
     )