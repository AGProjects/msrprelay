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

from sqlobject import sqlhub, connectionForURI, SQLObject, StringCol, BLOBCol
from sqlobject.dberrors import Error as SQLObjectError

from application.configuration import *
from application.configuration.datatypes import Boolean

from twisted.internet.threads import deferToThread

from msrp.digest import LoginFailed

import cjson

class Config(ConfigSection):
    _datatypes = {"cleartext_passwords": Boolean}
    cleartext_passwords = True
    uri = "mysql://user:pass@db/sipthor"
    subscriber_table = "sip_accounts"
    username_col = "username"
    domain_col = "domain"
    profile_col = "profile"

config = ConfigFile("config.ini")
config.read_settings("SIPThor", Config)

class Subscribers(SQLObject):
    class sqlmeta:
        table = Config.subscriber_table
    username = StringCol(dbName = Config.username_col)
    domain = StringCol(dbName = Config.domain_col)
    profile = BLOBCol(dbName = Config.profile_col)

sqlhub.processConnection = connectionForURI(Config.uri)

class Checker(object):

    def __init__(self):
        self.cleartext_passwords = Config.cleartext_passwords

    def _retrieve(self, col, username, domain):
        try:
            subscriber = Subscribers.selectBy(username=username, domain=domain)[0]
        except IndexError:
            raise LoginFailed("Username not found")
        except SQLObjectError:
            raise LoginFailed("Database error")
        try:
            profile = cjson.decode(subscriber.profile)
        except cjson.DecodeError:
            raise LoginFailed("Database JSON error")
        try:
            return profile[col]
        except KeyError:
            raise LoginFailed("Database profile error")

    def retrieve_password(self, username, domain):
        return deferToThread(self._retrieve, "password", username, domain)

    def retrieve_ha1(self, username, domain):
        return deferToThread(self._retrieve, "ha1", username, domain)
