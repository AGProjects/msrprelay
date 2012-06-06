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

import cjson
import signal

from application import log
from application.configuration import ConfigSection, ConfigSetting
from application.python.types import Singleton
from application.system import host
from application.process import process
from gnutls.interfaces.twisted import X509Credentials
from gnutls.constants import COMP_DEFLATE, COMP_LZO, COMP_NULL
from sqlobject import sqlhub, connectionForURI, SQLObject, StringCol, BLOBCol
from sqlobject.dberrors import Error as SQLObjectError
from twisted.internet.threads import deferToThread

from msrp import configuration_filename, __version__
from msrp.digest import LoginFailed
from msrp.tls import Certificate, PrivateKey

from thor.eventservice import EventServiceClient, ThorEvent
from thor.entities import ThorEntitiesRoleMap, GenericThorEntity as ThorEntity
from thor.tls import X509NameValidator


class Config(ConfigSection):
    __cfgfile__ = configuration_filename
    __section__ = 'SIPThor'

    cleartext_passwords = True
    uri = "mysql://user:pass@db/sipthor"
    subscriber_table = "sip_accounts"
    username_col = "username"
    domain_col = "domain"
    profile_col = "profile"
    multiply = 1000
    certificate = ConfigSetting(type=Certificate, value=None)
    private_key = ConfigSetting(type=PrivateKey, value=None)
    ca = ConfigSetting(type=Certificate, value=None)

class ThorNetworkConfig(ConfigSection):
    __cfgfile__ = configuration_filename
    __section__ = 'ThorNetwork'

    domain = "sipthor-domain"
    passport = X509NameValidator('O:undefined, OU:undefined')


class Subscribers(SQLObject):
    class sqlmeta:
        table = Config.subscriber_table
    username = StringCol(dbName = Config.username_col)
    domain = StringCol(dbName = Config.domain_col)
    profile = BLOBCol(dbName = Config.profile_col)

sqlhub.processConnection = connectionForURI(Config.uri)


class ThorNetworkService(EventServiceClient):
    __metaclass__ = Singleton
    topics = ["Thor.Members"]

    def __init__(self):
        self.node = ThorEntity(host.default_ip, ['msrprelay_server'], version=__version__)
        self.networks = {}
        self.presence_message = ThorEvent('Thor.Presence', self.node.id)
        self.shutdown_message = ThorEvent('Thor.Leave', self.node.id)
        credentials = X509Credentials(Config.certificate, Config.private_key, [Config.ca])
        credentials.verify_peer = True
        credentials.session_params.compressions = (COMP_LZO, COMP_DEFLATE, COMP_NULL)
        EventServiceClient.__init__(self, ThorNetworkConfig.domain, credentials)
        process.signals.add_handler(signal.SIGHUP, self._handle_SIGHUP)
        process.signals.add_handler(signal.SIGINT, self._handle_SIGINT)
        process.signals.add_handler(signal.SIGTERM, self._handle_SIGTERM)

    def handle_event(self, event):
        # print "Received event: %s" % event
        networks = self.networks
        role_map = ThorEntitiesRoleMap(event.message) ## mapping between role names and lists of nodes with that role
        for role in ["msrprelay_server"]:
            try:
                network = networks[role] ## avoid setdefault here because it always evaluates the 2nd argument
            except KeyError:
                from thor import network as thor_network
                network = thor_network.new(Config.multiply)
                networks[role] = network
            new_nodes = set([node.ip for node in role_map.get(role, [])])
            old_nodes = set(network.nodes)
            added_nodes = new_nodes - old_nodes
            removed_nodes = old_nodes - new_nodes
            if removed_nodes:
                for node in removed_nodes:
                    network.remove_node(node)
                plural = len(removed_nodes) != 1 and 's' or ''
                log.msg("removed %s node%s: %s" % (role, plural, ', '.join(removed_nodes)))
            if added_nodes:
                for node in added_nodes:
                    network.add_node(node)
                plural = len(added_nodes) != 1 and 's' or ''
                log.msg("added %s node%s: %s" % (role, plural, ', '.join(added_nodes)))
            #print "Thor %s nodes: %s" % (role, str(network.nodes))


class Checker(object):
    def __init__(self):
        self.cleartext_passwords = Config.cleartext_passwords
        self._thor_service = ThorNetworkService()

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
