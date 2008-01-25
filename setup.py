#!/usr/bin/env python

from distutils.core import setup
from msrp import __version__

setup(name             = "msrprelay",
      version          = __version__,
      author           = "Ruud Klaver",
      author_email     = "ruud@ag-projects.com",
      maintainer       = "Ruud Klaver",
      maintainer_email = "ruud@ag-projects.com",
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
      packages         = ['msrp', 'msrp.backend'],
      scripts          = ['msrprelay']
      )
