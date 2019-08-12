
from copy import copy
from collections import deque

from application import log
from application.configuration import *
from application.configuration.datatypes import NetworkAddress, LogLevel
from application.python.types import Singleton
from application.system import host

from zope.interface import implements
from twisted.internet.defer import maybeDeferred
from twisted.internet import reactor
from twisted.internet.protocol import Factory, ClientFactory
from twisted.internet.interfaces import IPullProducer

from gnutls.interfaces.twisted import TLSContext, X509Credentials

from msrp.tls import Certificate, PrivateKey
from msrp.protocol import *
from msrp.digest import AuthChallenger, LoginFailed
from msrp.responses import *
from msrp import configuration_filename


class RelayConfig(ConfigSection):
    __cfgfile__ = configuration_filename
    __section__ = 'Relay'

    address = ConfigSetting(type=NetworkAddress, value=NetworkAddress("0.0.0.0:2855"))
    hostname = ""
    default_domain = ""
    allow_other_methods = True
    session_expiration_time_minimum = 60
    session_expiration_time_default = 600
    session_expiration_time_maximum = 3600
    auth_challenge_expiration_time = 15
    backend = "database"
    max_auth_attempts = 3
    debug_notls = False
    log_failed_auth = False
    certificate = ConfigSetting(type=Certificate, value=None)
    key = ConfigSetting(type=PrivateKey, value=None)
    log_level = ConfigSetting(type=LogLevel, value=log.level.DEBUG)


class Relay(object):
    __metaclass__ = Singleton

    def __init__(self):
        self.unbound_sessions = {}
        self._do_init()

    def _do_init(self):
        self.listener = None
        self.backend = __import__("msrp.backend.%s" % RelayConfig.backend.lower(), globals(), locals(), [""]).Checker()
        if not RelayConfig.debug_notls:
            if RelayConfig.certificate is None:
                raise RuntimeError("TLS certificate file is not specified in configuration or is invalid")
            if RelayConfig.key is None:
                raise RuntimeError("TLS private key file is not specified in configuration or is invalid")
            self.credentials = X509Credentials(RelayConfig.certificate, RelayConfig.key)
            self.credentials.verify_peer = False
            # TODO: add configuration option for configuring session parameters? -Saul
        if RelayConfig.hostname != "":
            self.hostname = RelayConfig.hostname
            if not RelayConfig.debug_notls:
                def matches(hostname, pattern):
                    if pattern.startswith('*.'):
                        return hostname.endswith(pattern[1:])
                    else:
                        return hostname == pattern
                if not any(matches(self.hostname, name) for name in RelayConfig.certificate.alternative_names.dns):
                    raise RuntimeError('The specified MSRP Relay hostname "%s" is not set as DNS subject alternative name in the TLS certificate.' % self.hostname)
        elif not RelayConfig.debug_notls:
            self.hostname = RelayConfig.certificate.alternative_names.dns[0] # Just grab the first one?
        elif RelayConfig.address[0] != "0.0.0.0":
            self.hostname = RelayConfig.address[0]
        else:
            self.hostname = host.default_ip
        self.auth_challenger = AuthChallenger(RelayConfig.auth_challenge_expiration_time)

    def _do_run(self):
        if RelayConfig.debug_notls:
            self.listener = reactor.listenTCP(RelayConfig.address[1], RelayFactory(), interface=RelayConfig.address[0])
        else:
            self.listener = reactor.listenTLS(RelayConfig.address[1], RelayFactory(), TLSContext(self.credentials), interface=RelayConfig.address[0])

    def run(self):
        self._do_run()
        reactor.run()

    def reload(self):
        log.debug("Reloading configuration file")
        RelayConfig.reset()
        RelayConfig.read()
        if not self.listener:
            try:
                self._do_init()
            except RuntimeError, e:
                log.fatal("Error reloading configuration file: %s" % e)
                reactor.stop()
        else:
            result = self.listener.stopListening()
            result.addCallback(lambda x: self._do_init())
            result.addCallbacks(lambda x: self._do_run(), self._reload_failure)

    def _reload_failure(self, failure):
        failure.trap(RuntimeError)
        log.fatal("Error reloading configuration file: %s" % failure.value)
        reactor.stop()

    def generate_uri(self):
        return URI(self.hostname, port=RelayConfig.address[1], use_tls=not RelayConfig.debug_notls)


class RelayFactory(Factory):
    protocol = MSRPProtocol
    noisy = False

    def get_peer(self, protocol):
        peer = Peer(protocol = protocol)
        return peer


class ConnectingFactory(ClientFactory):
    protocol = MSRPProtocol
    noisy = False

    def __init__(self, peer):
        self.peer = peer

    def get_peer(self, protocol):
        self.peer.got_protocol(protocol)
        return self.peer

    def clientConnectionFailed(self, connector, reason):
        self.peer.connection_failed(reason.value)


class ForwardingData(object):
    def __init__(self, msrpdata):
        self.msrpdata_received = msrpdata
        self.msrpdata_forward = None
        self.bytes_received = 0
        self.data_queue = deque()
        self.continuation = None

    def __str__(self):
        return str(self.msrpdata_received)

    @property
    def method(self):
        return self.msrpdata_received.method

    @property
    def bytes_in_queue(self):
        return sum(len(data) for data in self.data_queue)

    def add_data(self, data):
        self.bytes_received += len(data)
        self.data_queue.append(data)

    def consume_data(self):
        if self.data_queue:
            return self.data_queue.popleft()
        else:
            return None


class ForwardingSendData(ForwardingData):
    def __init__(self, msrpdata):
        super(ForwardingSendData, self).__init__(msrpdata)
        self.position = msrpdata.headers["Byte-Range"].decoded[0]


# A session always exists of two peer instances that are associated with
# eachother.
#
# A Peer instance has an attribute state, which can be one of the following:
#
# NEW:
# A newly created incoming connection. If an AUTH is received and successfully
# processed this creates a new session and moves the Peer into the UNBOUND
# state. Alternatively, a SEND for an existing session can be received, which
# directly binds the Peer with the session and moves it into ESTABLISHED.
#
# UNBOUND:
# A newly created session which does not yet have another endpoint associated
# with it. This association can occur either through a new outgoing connection
# when the client that performed the AUTH sends a SEND message or when a new
# SEND message is received.
#
# CONNECTING:
# An attempt at a new outgoing connection. Messages can already be queued on it.
# When the protocol is connected the Peer will move into ESTABLISHED.
#
# ESTABLISHED:
# The two endpoints for the session are known and messages can be passed through
# in either direction. When the connection to this peer is lost, the Peer will
# move into DISCONNECTED, when the connection to the other peer is lost it will
# move into DISCONNECTING.
#
# DISCONNECTING:
# The connection to the other peer is lost and relay has to send REPORTs for
# queued messages that require it. After this it will disconnect itself.
#
# DISCONNECTED:
# When the peer is disconnected, which can happen at any time, inform the other
# associated peer. This is always the end state.
#
#          |                                 |
#          V                                 V
#       +-----+                        +------------+
# +-----| NEW |---------+     +--------| CONNECTING |-----+
# |     +-----+         |     |        +------------+     |
# |        |            |     |                           |
# |        V            V     V                           |
# |   +---------+   +-------------+   +---------------+   |
# |<--| UNBOUND |-->| ESTABLISHED |-->| DISCONNECTING |-->|
# |   +---------+   +-------------+   +---------------+   |
# |                        |                              |
# |                        V                              |
# |                 +--------------+                      |
# +---------------->| DISCONNECTED |<---------------------+
#                   +--------------+


class Peer(object):
    implements(IPullProducer)

    def __init__(self, session = None, protocol = None, path = None, other_peer = None):
        self.session = session
        self.protocol = protocol
        self.other_peer = other_peer
        self.path = path
        if self.protocol is not None:
            self.state = "NEW"
            self.auth_attempts = 0
            self.invalid_timer = reactor.callLater(30, self._cb_invalid)
        else:
            self.invalid_timer = None
            self.state = "CONNECTING"
        self.send_transactions = {}
        self.other_transactions = {}  # Other requests not REPORT or SEND
        self.forwarding_data = None
        # transmission attributes
        self.registered = False
        self.forwarding_send_request = False
        self.forward_send_queue = deque()
        self.forward_other_queue = deque()
        self.read_paused = False
        self.relay = Relay()

    def __str__(self):
        if self.session is None:
            address = self.protocol.transport.getPeer()
            return "%s:%d (%s)" % (address.host, address.port, self.state)
        else:
            return "session %s for %s@%s (%s)" % (self.session.session_id, self.session.username, self.session.realm, self.state)

    def log(self, log_func, msg):
        log_func("%s: %s" % (str(self), msg))

    # called by MSRPProtocol

    def data_start(self, msrpdata):
        #self.log(log.debug, "Received headers for %s" % str(msrpdata))
        if self.state == "NEW":
            result = maybeDeferred(self._unbound_peer_data, msrpdata)
            result.addErrback(self._cb_catch_response, msrpdata)
        else:
            self._bound_peer_data(msrpdata)

    def write_chunk(self, chunk):
        #self.log(log.debug, "Received %d bytes of MSRP body" % len(chunk))
        if self.state == "ESTABLISHED" and self.forwarding_data:
            self.forwarding_data.add_data(chunk)
            if self.forwarding_data.method != 'SEND' and self.forwarding_data.bytes_in_queue > 10240:
                self.log(log.debug, "Non-SEND request's payload bigger than 10KB, closing connection")
                del self.other_transactions[self.forwarding_data.msrpdata_forward.transaction_id]
                self.forwarding_data = None
                self.protocol.transport.loseConnection()
                return
            self.other_peer._maybe_pause_read()
            self.other_peer.start_sending()

    def data_end(self, continuation):
        #self.log(log.debug, "Received termination \"%s\"" % continuation)
        if self.state == "ESTABLISHED" and self.forwarding_data:
            msrpdata = self.forwarding_data.msrpdata_received
            if msrpdata.method == "SEND":
                if msrpdata.failure_report != "no":
                    if msrpdata.failure_report == "yes":
                        self.enqueue(ResponseOK(msrpdata).data.encode())
                    self.send_transactions[self.forwarding_data.msrpdata_forward.transaction_id] = (self.forwarding_data, None)
                self.forwarding_data.continuation = continuation
            else:
                if msrpdata.method != 'REPORT' and msrpdata.failure_report != 'no':
                    # Keep track, for matching replies
                    timer = reactor.callLater(30, self._cb_transaction_timeout, self.forwarding_data)
                    self.other_transactions[self.forwarding_data.msrpdata_forward.transaction_id] = (self.forwarding_data, timer)
                # For methods other than SEND, assemble the chunk and don't use ForwardingData
                self.forwarding_data.msrpdata_forward.data = ''.join(self.forwarding_data.data_queue)
                self.other_peer.enqueue(self.forwarding_data.msrpdata_forward.encode(continuation))
            self.other_peer.start_sending()
            self.forwarding_data = None

    def connection_lost(self, reason):
        self.log(log.debug, "Connection lost: %s" % reason)
        if self.invalid_timer and self.invalid_timer.active():
            self.invalid_timer.cancel()
            self.invalid_timer = None
        if self.state == "ESTABLISHED":
            self.other_peer.disconnect()
        if self.state == "UNBOUND":
            del self.relay.unbound_sessions[self.session.session_id]
        self.state = "DISCONNECTED"
        if self.session is not None and self is self.session.source:
            self.log(log.debug, "bytes sent: %d, bytes received: %d" % (self.session.upstream_bytes, self.session.downstream_bytes))
        self._cleanup()

    # called by ConnectingFactory

    def connection_failed(self, reason):
        self.log(log.warn, "Connection failed: %s" % reason)
        if self.state == "CONNECTING":
            self.other_peer.disconnect()
        self._cleanup()

    # methods for an unbound peer

    def _cb_invalid(self):
        self.log(log.warn, "No valid MSRP message received, disconnecting")
        self.invalid_timer = None
        self.disconnect()

    def _cb_catch_response(self, failure, msrpdata):
        failure.trap(ResponseException)
        if msrpdata.method is None:
            self.log(log.warn, "Caught exception to response: %s (%s)" % (failure.value.__class__.__name__, failure.value.data.comment))
            return
        response = failure.value.data
        #self.log(log.debug, "Sending response %03d (%s)" % (response.code, response.comment))
        self.enqueue(response.encode())

    def _unbound_peer_data(self, msrpdata):
        try:
            msrpdata.verify_headers()
        except ParsingError, e:
            if isinstance(e, HeaderParsingError) and (e.header == "To-Path" or e.header == "From-Path"):
                self.log(log.warn, "Cannot send error response, path headers unreadable")
                return
            else:
                raise ResponseUnintelligible(msrpdata, e.args[0])
        # Check if To-Path is really directed to us.
        to_path = msrpdata.headers["To-Path"].decoded
        from_path = msrpdata.headers["From-Path"].decoded
        if msrpdata.method == "AUTH" and len(to_path) == 1:
            return self._handle_auth(msrpdata)
        elif msrpdata.method == "SEND" and len(to_path) > 1:
            session_id = to_path[0].session_id
            try:
                session = self.relay.unbound_sessions[session_id]
            except KeyError:
                raise ResponseNoSession(msrpdata)
            self.log(log.debug, "Found matching unbound session %s" % session.session_id)
            self.state = "ESTABLISHED"
            self.invalid_timer.cancel()
            self.invalid_timer = None
            self.session = session
            self.path = from_path
            self.other_peer = self.session.source
            self.other_peer.got_destination(self)
            self._bound_peer_data(msrpdata)
        else:
            raise ResponseUnknownMethod(msrpdata)

    def _handle_auth(self, msrpdata):
        auth_challenger = self.relay.auth_challenger
        if RelayConfig.default_domain == "":
            realm = msrpdata.headers["To-Path"].decoded[0].host
        else:
            realm = RelayConfig.default_domain
        if not msrpdata.headers.has_key("Authorization"):
            # If the Authorization header is not present generate challenge data and respond.
            www_authenticate = auth_challenger.generate_www_authenticate(realm, self.protocol.transport.getPeer().host)
            raise ResponseUnauthenticated(msrpdata, headers = [WWWAuthenticateHeader(www_authenticate)])
        else:
            authorization = msrpdata.headers["Authorization"].decoded
            if authorization.get("realm") != realm:
                raise ResponseUnauthorized(msrpdata, "realm does not match")
            if authorization.get("qop") != "auth":
                raise ResponseUnauthorized(msrpdata, "qop != auth")
            try:
                username = authorization["username"]
                session_id = authorization["nonce"]
            except KeyError, e:
                raise ResponseUnauthorized(msrpdata, "%s field not present in Authorization header" % e.args[0])
            if self.relay.backend.cleartext_passwords:
                result = self.relay.backend.retrieve_password(username, realm)
                func = auth_challenger.process_authorization_password
            else:
                result = self.relay.backend.retrieve_ha1(username, realm)
                func = auth_challenger.process_authorization_ha1
            result.addCallback(func, "AUTH", msrpdata.headers["To-Path"].encoded.split()[-1], self.protocol.transport.getPeer().host, **authorization)
            result.addCallbacks(self._cb_login_success, self._eb_login_failed, callbackArgs=[msrpdata, session_id, username, realm], errbackArgs=[msrpdata])
            return result

    def _eb_login_failed(self, failure, msrpdata):
        failure.trap(LoginFailed)
        self.auth_attempts += 1
        if RelayConfig.log_failed_auth:
            try:
                username = msrpdata.headers["Authorization"].decoded["username"]
            except IndexError:
                self.log(log.warn, "AUTH failed, no username: %s" % failure.value.args[0])
            else:
                self.log(log.warn, 'AUTH failed for username "%s": %s' % (username, failure.value.args[0]))
        if self.auth_attempts == RelayConfig.max_auth_attempts:
            self.disconnect()
        else:
            raise ResponseUnauthorized(msrpdata, "Login failed: %s" % failure.value.args[0])

    def _cb_login_success(self, authentication_info, msrpdata, session_id, username, realm):
        # Check the Expires header, if present.
        if msrpdata.headers.has_key("Expires"):
            expire = msrpdata.headers["Expires"].decoded
            if expire < RelayConfig.session_expiration_time_minimum:
                raise ResponseOutOfBounds(msrpdata, headers = [MinExpiresHeader(RelayConfig.session_expiration_time_minimum)])
            if expire > RelayConfig.session_expiration_time_maximum:
                raise ResponseOutOfBounds(msrpdata, headers = [MaxExpiresHeader(RelayConfig.session_expiration_time_maximum)])
        else:
            expire = RelayConfig.session_expiration_time_default
        # We got a successful AUTH request, so add a new session
        # and reply with the the Use-Path.
        self.state = "UNBOUND"
        self.invalid_timer.cancel()
        self.invalid_timer = None
        from_path = msrpdata.headers["From-Path"].decoded
        self.path = from_path
        self.relay.unbound_sessions[session_id] = self.session = Session(self, session_id, expire, username, realm)
        use_path = copy(from_path)
        use_path.pop()
        use_path = list(reversed(use_path))
        uri = self.relay.generate_uri()
        uri.session_id = session_id
        use_path.append(uri)
        headers = [UsePathHeader(use_path), ExpiresHeader(expire), AuthenticationInfoHeader(authentication_info)]
        self.log(log.debug, "AUTH succeeded, creating new session")
        raise ResponseOK(msrpdata, headers = headers)

    # methods for a unconnected peer

    def got_protocol(self, protocol):
        self.log(log.debug, "Successfully connected")
        self.state = "ESTABLISHED"
        self.protocol = protocol
        if self.forward_other_queue or self.forward_send_queue:
            self.start_sending()

    def got_destination(self, other_peer):
        self.state = "ESTABLISHED"
        del self.relay.unbound_sessions[self.session.session_id]
        self.session.destination = other_peer
        self.other_peer = other_peer

    # methods for a bound and connected peer

    def _bound_peer_data(self, msrpdata):
        try:
            try:
                msrpdata.verify_headers()
            except ParsingError, e:
                if isinstance(e, HeaderParsingError) and (e.header == "To-Path" or e.header == "From-Path"):
                    self.log(log.error, "Cannot send error response, path headers unreadable")
                    return
                else:
                    raise ResponseUnintelligible(msrpdata, e.args[0])
            to_path = copy(msrpdata.headers["To-Path"].decoded)
            from_path = copy(msrpdata.headers["From-Path"].decoded)
            relay_uri = to_path.popleft()
            if relay_uri.session_id != self.session.session_id:
                raise ResponseNoSession(msrpdata, "Wrong session id on relay MSRP URI")
            if len(to_path) == 0 and msrpdata.method not in (None, "AUTH"):
                    raise ResponseNoSession(msrpdata, "Non-response with me as endpoint, nowhere to relay to")
            for index, uri in enumerate(from_path):
                if uri != self.path[index]:
                    raise ResponseNoSession(msrpdata, "From-Path does not match session source")
            if msrpdata.method == "AUTH":
                if msrpdata.headers.has_key("Expires"):
                    expire = msrpdata.headers["Expires"].decoded
                    if expire < RelayConfig.session_expiration_time_minimum:
                        raise ResponseOutOfBounds(msrpdata, headers=[MinExpiresHeader(RelayConfig.session_expiration_time_minimum)])
                    if expire > RelayConfig.session_expiration_time_maximum:
                        raise ResponseOutOfBounds(msrpdata, headers=[MaxExpiresHeader(RelayConfig.session_expiration_time_maximum)])
                else:
                    expire = RelayConfig.session_expiration_time_default
                use_path = from_path
                use_path.pop()
                use_path = list(reversed(use_path))
                use_path.append(relay_uri)
                headers = [UsePathHeader(use_path), ExpiresHeader(expire)]
                self.log(log.debug, "Received refreshing AUTH")
                raise ResponseOK(msrpdata, headers=headers)
            if self.state == "UNBOUND":
                if msrpdata.method != "SEND":
                    raise ResponseNoSession(msrpdata, "Non-SEND method received on unbound session")
                self.got_destination(Peer(path = to_path, session = self.session, other_peer = self))
                uri = to_path[0]
                #self.log(log.debug, "Attempting to connect to %s" % str(uri))
                factory = ConnectingFactory(self.other_peer)
                if uri.use_tls:
                    self.other_peer.connector = reactor.connectTLS(uri.host, uri.port, factory, TLSContext(self.relay.credentials))
                else:
                    self.other_peer.connector = reactor.connectTCP(uri.host, uri.port, factory)
            else:
                for index, uri in enumerate(to_path):
                    if uri != self.other_peer.path[index]:
                        raise ResponseNoSession(msrpdata, "To-Path does not match session destination")
            if msrpdata.method == "SEND":
                if not msrpdata.headers.has_key("Message-ID"):
                    raise ResponseUnintelligible(msrpdata, "SEND received without Message-ID")
                if not msrpdata.headers.has_key("Byte-Range"):
                    raise ResponseUnintelligible(msrpdata, "SEND received without Byte-Range")
            if msrpdata.method is None:    # we got a response
                if msrpdata.transaction_id in self.other_peer.send_transactions:
                    # Handle response to SEND request with Failure-Report != no
                    forwarding_data, timer = self.other_peer.send_transactions.pop(msrpdata.transaction_id)
                    if timer is not None:
                        timer.cancel()
                    if msrpdata.code != ResponseOK.code:
                        report = generate_report(msrpdata.code, forwarding_data, reason=msrpdata.comment)
                        self.other_peer.enqueue(report.encode())
                elif msrpdata.transaction_id in self.other_peer.other_transactions:
                    forwarding_data, timer = self.other_peer.other_transactions.pop(msrpdata.transaction_id)
                    if timer is not None:
                        timer.cancel()
                    forward = msrpdata
                    forward.transaction_id = forwarding_data.msrpdata_received.transaction_id
                    to_path_header = msrpdata.headers["To-Path"]
                    to_path = to_path_header.decoded
                    from_path_header = msrpdata.headers["From-Path"]
                    from_path = from_path_header.decoded
                    from_path.appendleft(to_path.popleft())
                    to_path_header.decoded = to_path
                    from_path_header.decoded = from_path
                    self.other_peer.enqueue(forward.encode())
                else:
                    self.log(log.debug, "Received response for untracked request: %s" % msrpdata)
            elif msrpdata.method in ("SEND", "REPORT", "NICKNAME") or RelayConfig.allow_other_methods:
                # Do the magic of appending the first To-Path URI to the From-Path.
                to_path = copy(msrpdata.headers["To-Path"].decoded)
                from_path = copy(msrpdata.headers["From-Path"].decoded)
                from_path.appendleft(to_path.popleft())
                forward = MSRPData(generate_transaction_id(), method=msrpdata.method)
                for header in msrpdata.headers.itervalues():
                    forward.add_header(MSRPHeader(header.name, header.encoded))
                forward.add_header(ToPathHeader(to_path))
                forward.add_header(FromPathHeader(from_path))
                if msrpdata.method == 'SEND':
                    self.forwarding_data = ForwardingSendData(msrpdata)
                else:
                    self.forwarding_data = ForwardingData(msrpdata)
                self.forwarding_data.msrpdata_forward = forward
                if self.forwarding_data.method == 'SEND':
                    if msrpdata.failure_report != "no":
                        self.send_transactions[self.forwarding_data.msrpdata_forward.transaction_id] = (self.forwarding_data, None)
                    self.other_peer.enqueue(self.forwarding_data)
                else:
                    self.other_transactions[self.forwarding_data.msrpdata_forward.transaction_id] = (self.forwarding_data, None)
            else:
                raise ResponseUnknownMethod(msrpdata)
        except ResponseException, e:
            if msrpdata.method is None:
                self.log(log.debug, "Caught exception to response: %s (%s)" % (e.__class__.__name__, e.data.comment))
                return
            response = e.data
            self.enqueue(response.encode())

    def _cb_transaction_timeout(self, forward_data):
        transaction_id = forward_data.msrpdata_forward.transaction_id
        if forward_data.method == 'SEND':
            del self.send_transactions[transaction_id]
            if forward_data.msrpdata_received.failure_report == 'yes':
                report = generate_report(ResponseDownstreamTimeout.code, forward_data)
                self.enqueue(report.encode())
        else:
            # We don't really need to do anything here, just remove the request from the mapping
            del self.other_transactions[transaction_id]

    def enqueue(self, msrpdata):
        #self.log(log.debug, "Enqueuing %s" % str(msrpdata))
        if isinstance(msrpdata, ForwardingData):
            self.forward_send_queue.append(msrpdata)
        else:    # a string containing a request or response
            self.forward_other_queue.append(msrpdata)
        self._maybe_pause_read()
        self.start_sending()

    def start_sending(self):
        if self.state not in ["CONNECTING", "DISCONNECTED"] and not self.registered:
            #self.log(log.debug, "Starting transmission")
            self.registered = True
            self.protocol.transport.registerProducer(self, False)

    def _stop_sending(self):
        #self.log(log.debug, "Empty queues, halting transmission")
        self.registered = False
        self.protocol.transport.unregisterProducer()
        if self.state == "DISCONNECTING":
            self.state = "DISCONNECTED"
            self.protocol.transport.loseConnection()

    def disconnect(self):
        #self.log(log.debug, "Disconnecting when possible")
        if self.invalid_timer and self.invalid_timer.active():
            self.invalid_timer.cancel()
            self.invalid_timer = None
        if self.state == "NEW":
            self.protocol.transport.loseConnection()
            self.state = "DISCONNECTED"
        elif self.state == "UNBOUND":
            del self.relay.unbound_sessions[self.session.session_id]
            self.protocol.transport.loseConnection()
            self.state = "DISCONNECTED"
        elif self.state == "CONNECTING":
            self.connector.disconnect()
            self.state = "DISCONNECTED"
        elif self.state == "ESTABLISHED":
            for forwarding_data, timer in self.send_transactions.itervalues():
                if timer is not None:
                    timer.cancel()
                report = generate_report(ResponseDownstreamTimeout.code, forwarding_data, reason="Session got disconnected")
                self.enqueue(report.encode())
            self.send_transactions.clear()
            for _, timer in self.other_transactions.itervalues():
                if timer is not None:
                    timer.cancel()
            self.other_transactions.clear()
            if not self.registered:
                self.protocol.transport.loseConnection()
                self.state = "DISCONNECTED"
            else:
                self.state = "DISCONNECTING"

    def _cleanup(self):
        self.session = None
        self.other_peer = None
        self.protocol = None
        self.relay = None
        for _, timer in self.send_transactions.itervalues():
            if timer is not None and timer.active():
                timer.cancel()
        self.send_transactions.clear()
        for _, timer in self.other_transactions.itervalues():
            if timer is not None and timer.active():
                timer.cancel()
        self.other_transactions.clear()
        self.forward_send_queue.clear()
        self.forward_other_queue.clear()

    @property
    def _data_bytes(self):
        return sum(data.bytes_in_queue for data in self.forward_send_queue)

    @property
    def _message_count(self):
        return len(self.forward_other_queue) + len(self.forward_send_queue)

    def _maybe_pause_read(self):
        if self.state == "ESTABLISHED" and self.other_peer.state == "ESTABLISHED" and not self.other_peer.read_paused:
            if self._data_bytes > 1024 * 1024 or self._message_count > 50:
                self.other_peer.pause_read()

    def _maybe_resume_read(self):
        if self.state == "ESTABLISHED" and self.other_peer.state == "ESTABLISHED" and self.other_peer.read_paused:
            if self._data_bytes <= 1024 * 1024 and self._message_count <= 50:
                self.other_peer.resume_read()

    def pause_read(self):
        self.read_paused = True
        self.protocol.transport.stopReading()

    def resume_read(self):
        self.read_paused = False
        self.protocol.transport.startReading()

    # methods implemented for IPullProducer

    def resumeProducing(self):
        if self.forward_other_queue:
            if self.forwarding_send_request:
                #self.log(log.debug, "Sending other message, aborting SEND")
                data = self.forward_send_queue.popleft()
                # terminate the current chunk
                self._send_payload(data.msrpdata_forward.encode_end("+"))
                timer = reactor.callLater(30, self.other_peer._cb_transaction_timeout, data)
                self.other_peer.send_transactions[data.msrpdata_forward.transaction_id] = (data, timer)
                if self.other_peer.forwarding_data is data:
                    self.other_peer.forwarding_data = None
                # clone the forward data
                new_data = ForwardingSendData(data.msrpdata_received)
                new_data.continuation = data.continuation
                new_data.position = data.position
                new_data.data_queue, data.data_queue = data.data_queue, deque()
                new_data.msrpdata_forward = data.msrpdata_forward.clone()
                # adjust the byterange, create a new transaction
                new_data.msrpdata_forward.transaction_id = generate_transaction_id()
                byterange = new_data.msrpdata_forward.headers["Byte-Range"].decoded
                byterange[0] = new_data.position
                new_data.msrpdata_forward.headers["Byte-Range"].decoded = byterange
                self.forward_send_queue.appendleft(new_data)
                if self.other_peer.forwarding_data is None and new_data.continuation is None:
                    self.other_peer.forwarding_data = new_data
                self.forwarding_send_request = False
            else:
                #self.log(log.debug, "Sending message")
                self._send_payload(self.forward_other_queue.popleft())
            self._maybe_resume_read()
        elif self.forwarding_send_request:
            data = self.forward_send_queue[0]
            if data.continuation is not None and len(data.data_queue) <= 1:
                #self.log(log.debug, "Sending end of SEND message")
                self.forward_send_queue.popleft()
                chunk = data.consume_data()
                if chunk is not None:
                    self._send_payload(chunk)
                self._send_payload(data.msrpdata_forward.encode_end(data.continuation))
                if data.msrpdata_received.failure_report != 'no':
                    timer = reactor.callLater(30, self.other_peer._cb_transaction_timeout, data)
                    self.other_peer.send_transactions[data.msrpdata_forward.transaction_id] = (data, timer)
                self.forwarding_send_request = False
                self._maybe_resume_read()
            else:
                chunk = data.consume_data()
                if chunk is None:
                    self._stop_sending()
                else:
                    #self.log(log.debug, "Sending data for SEND message")
                    self._send_payload(chunk)
                    data.position += len(chunk)
                    self._maybe_resume_read()
        elif self.forward_send_queue:
            #self.log(log.debug, "Sending headers for SEND message")
            data = self.forward_send_queue[0]
            self.forwarding_send_request = True
            self._send_payload(data.msrpdata_forward.encode_start())
        else:
            self._stop_sending()

    def stopProducing(self):
        pass

    def _send_payload(self, data):
        if self.session is not None:
            if self is self.session.source:
                self.session.upstream_bytes += len(data)
            else:
                self.session.downstream_bytes += len(data)
        self.protocol.transport.write(data)


class Session(object):
    def __init__(self, source, session_id, expire, username, realm):
        self.source = source
        self.destination = None
        self.session_id = session_id
        self.expire = expire
        self.username = username
        self.realm = realm
        self.downstream_bytes = 0
        self.upstream_bytes = 0

