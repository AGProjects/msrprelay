#!/usr/bin/env python

import os
import re

from distutils.core import setup


def get_version():
    return re.search(r"""__version__\s+=\s+(?P<quote>['"])(?P<version>.+?)(?P=quote)""", open('msrp/__init__.py').read()).group('version')

def find_packages(toplevel):
    return [directory.replace(os.path.sep, '.') for directory, subdirs, files in os.walk(toplevel) if '__init__.py' in files]

setup(name             = "msrprelay",
      version          = get_version(),
      author           = "AG Projects",
      author_email     = "support@ag-projects.com",
      url              = "http://msrprelay.org/",
      description      = "A MSRP Relay.",
      license          = "GPL",
      platforms        = ["Platform Independent"],
      classifiers      = [
        "Development Status :: 4 - Beta",
        "Intended Audience :: Service Providers",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
      ],
      packages         = find_packages('msrp'),
      scripts          = ['msrprelay']
      )
