#!/usr/bin/env python3

import msrp
import os

from distutils.core import setup


def find_packages(toplevel):
    return [directory.replace(os.path.sep, '.') for directory, sub_dirs, files in os.walk(toplevel) if '__init__.py' in files]


setup(
    name='msrprelay',
    version=msrp.__version__,

    description='Python implementation of MSRP Relay (RFC4976)',
    url='http://msrprelay.org/',

    author='AG Projects',
    author_email='support@ag-projects.com',
    license='GPLv2',

    platforms=['Platform Independent'],
    classifiers=[
        'Development Status :: 5 - Production',
        'Intended Audience :: Service Providers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],

    data_files=[('/etc/msrprelay', ['config.ini.sample'])],
    packages=find_packages('msrp'),
    scripts=['msrprelay']
)
