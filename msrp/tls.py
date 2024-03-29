
__all__ = ['Certificate', 'PrivateKey']

from gnutls.crypto import X509Certificate, X509PrivateKey

from application.process import process

class _FileError(Exception): pass


def file_content(file):
    path = process.configuration.file(file)
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
    def __new__(cls, value):
        if isinstance(value, str):
            try:
                return X509Certificate(file_content(value))
            except Exception as e:
                raise ValueError("Certificate file '%s' could not be loaded: %s" % (value, str(e)))
        else:
            raise TypeError('value should be a string')


class PrivateKey(object):
    """Configuration data type. Used to create a gnutls.crypto.X509PrivateKey object
       from a file given in the configuration file."""
    def __new__(cls, value):
        if isinstance(value, str):
            try:
                return X509PrivateKey(file_content(value))
            except Exception as e:
                raise ValueError("Private key file '%s' could not be loaded: %s" % (value, str(e)))
        else:
            raise TypeError('value should be a string')
