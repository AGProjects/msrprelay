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

from sqlobject import sqlhub, connectionForURI, SQLObject, StringCol
from sqlobject.dberrors import Error as SQLObjectError

from application.configuration import *
from application.configuration.datatypes import Boolean

from twisted.internet.threads import deferToThread

from msrp.digest import LoginFailed
from msrp import configuration_filename

class Config(ConfigSection):
    cleartext_passwords = True
    uri = "mysql://user:pass@db/openser"
    subscriber_table = "subscriber"
    username_col = "username"
    domain_col = "domain"
    password_col = "password"
    ha1_col = "ha1"

config = ConfigFile(configuration_filename)
config.read_settings("Database", Config)

class Subscribers(SQLObject):
    class sqlmeta:
        table = Config.subscriber_table
    username = StringCol(dbName = Config.username_col)
    domain = StringCol(dbName = Config.domain_col)
    password = StringCol(dbName = Config.password_col)
    ha1 = StringCol(dbName = Config.ha1_col)

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
        return getattr(subscriber, col)

    def retrieve_password(self, username, domain):
        return deferToThread(self._retrieve, "password", username, domain)

    def retrieve_ha1(self, username, domain):
        return deferToThread(self._retrieve, "ha1", username, domain)
