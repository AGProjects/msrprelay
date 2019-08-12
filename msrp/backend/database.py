
from sqlobject import sqlhub, connectionForURI, SQLObject, StringCol
from sqlobject.dberrors import Error as SQLObjectError

from application.configuration import *

from twisted.internet.threads import deferToThread

from msrp.digest import LoginFailed
from msrp import configuration_file

class Config(ConfigSection):
    __cfgfile__ = configuration_file
    __section__ = 'Database'

    cleartext_passwords = True
    uri = "mysql://user:pass@db/opensips"
    subscriber_table = "subscriber"
    username_col = "username"
    domain_col = "domain"
    password_col = "password"
    ha1_col = "ha1"


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
