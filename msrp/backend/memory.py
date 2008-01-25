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

from application.configuration import *

from twisted.internet.defer import succeed, fail

from msrp.digest import LoginFailed

config = ConfigFile("config.ini")
config.cleartext_passwords = True
config.user_db = dict(config.parser.items("Memory"))

class Checker(object):

    def __init__(self):
       self.cleartext_passwords = config.cleartext_passwords

    def retrieve_password(self, username, domain):
        if username in config.user_db:
            return succeed(config.user_db[username])
        else:
            return fail(LoginFailed("Username not found"))
