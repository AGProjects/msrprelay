#    MSRP Relay
#    Copyright (C) 2008 AG Projects
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

__version__ = "1.0.6"

runtime_directory = "/var/run/msrprelay"
system_config_directory = "/etc/msrprelay"

configuration_filename = "config.ini"


package_requirements = {'python-application': '1.2.8',
                        'python-gnutls':      '1.1.8',
                        'twisted':            '2.5.0'}

try:
    from application.dependency import ApplicationDependencies, DependencyError
except ImportError:
    class DependencyError(Exception): pass

    class ApplicationDependencies(object):
        def __init__(self, *args, **kw):
            pass
        def check(self):
            required_version = package_requirements['python-application']
            raise DependencyError("need python-application version %s or higher but it's not installed" % required_version)

dependencies = ApplicationDependencies(**package_requirements)

