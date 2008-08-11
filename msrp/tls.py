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
__all__ = ['Certificate', 'PrivateKey']

from gnutls.crypto import X509Certificate,  X509PrivateKey

from application import log
from application.process import process
from application.configuration.datatypes import StringList

class _FileError(Exception): pass

def file_content(file):
    path = process.config_file(file)
    if path is None:
        raise _FileError("File '%s' does not exist" % file)
    try:
        f = open(path, 'rt')
    except:
        raise _FileError("File '%s' could not be open" % file)
    try:
        return f.read()
    finally:
        f.close()

class Certificate(object):
    """Configuration data type. Used to create a gnutls.crypto.X509Certificate object
       from a file given in the configuration file."""
    def __new__(typ, value):
        if isinstance(value, str):
            try:
                return X509Certificate(file_content(value))
            except Exception, e:
                log.warn("Certificate file '%s' could not be loaded: %s" % (value, str(e)))
                return None
        else:
            raise TypeError, 'value should be a string'

class PrivateKey(object):
    """Configuration data type. Used to create a gnutls.crypto.X509PrivateKey object
       from a file given in the configuration file."""
    def __new__(typ, value):
        if isinstance(value, str):
            try:
                return X509PrivateKey(file_content(value))
            except Exception, e:
                log.warn("Private key file '%s' could not be loaded: %s" % (value, str(e)))
                return None
        else:
            raise TypeError, 'value should be a string'
