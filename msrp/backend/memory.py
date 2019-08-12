
from application.configuration import *

from twisted.internet.defer import succeed, fail

from msrp.digest import LoginFailed
from msrp import configuration_file

config = ConfigFile(configuration_file)
config.cleartext_passwords = True
config.user_db = dict(config.get_section("Memory", default=[]))

class Checker(object):

    def __init__(self):
       self.cleartext_passwords = config.cleartext_passwords

    def retrieve_password(self, username, domain):
        key = "%s@%s" % (username, domain)
        if key in config.user_db:
            return succeed(config.user_db[key])
        else:
            return fail(LoginFailed("Username not found"))
