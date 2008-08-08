#!/usr/bin/env python

import sys
import time
from base64 import b64encode
from getpass import getpass

from twisted.names.srvconnect import SRVConnector
from twisted.internet.protocol import ClientFactory, Protocol
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet import reactor

from gnutls.constants import *
from gnutls.crypto import *
from gnutls.errors import *
from gnutls.interfaces.twisted import X509Credentials

from msrp.protocol import *
from msrp.digest import process_www_authenticate
from msrp.responses import *

rand_source = open("/dev/urandom")

def generate_transaction_id():
    return b64encode(rand_source.read(12), "+-")

class MSRPFileReceiverFactory(ClientFactory):
    protocol = MSRPProtocol

    def __init__(self, username, password, relay_uri):
        self.uri = URI("localhost", use_tls = True, port = 12345, session_id = b64encode(rand_source.read(12)))
        self.username = username
        self.password = password
        self.relay_uri = relay_uri
        self.byte_count = 0
        self.bytes_expected = 0
        self.do_on_start = None
        self.do_on_data = None
        self.do_on_end = None

    def get_peer(self, protocol):
        self.protocol = protocol
        reactor.callLater(0, self._send_auth1)
        return self

    def data_start(self, msrpdata):
        if self.do_on_start:
            self.do_on_start(msrpdata)

    def write_chunk(self, data):
        self.byte_count += len(data)
        print "received %d of %d bytes" % (self.byte_count, self.bytes_expected)
        if self.do_on_data:
            self.do_on_data(data)

    def data_end(self, continuation):
        if self.do_on_end:
            self.do_on_end(continuation)

    def connection_lost(self, reason):
        print "Connection lost!"

    def _send_auth1(self):
        print "Sending initial AUTH"
        msrpdata = MSRPData(generate_transaction_id(), method = "AUTH")
        msrpdata.add_header(ToPathHeader([self.relay_uri]))
        msrpdata.add_header(FromPathHeader([self.uri]))
        self.protocol.transport.write(msrpdata.encode())
        self.do_on_start = self._send_auth2

    def _send_auth2(self, msrpdata):
        print "Got challenge, sending response AUTH"
        auth, rsp_auth = process_www_authenticate(self.username, self.password, "AUTH", str(self.relay_uri), **msrpdata.headers["WWW-Authenticate"].decoded)
        msrpdata = MSRPData(generate_transaction_id(), method = "AUTH")
        msrpdata.add_header(ToPathHeader([self.relay_uri]))
        msrpdata.add_header(FromPathHeader([self.uri]))
        msrpdata.add_header(AuthorizationHeader(auth))
        self.protocol.transport.write(msrpdata.encode())
        self.do_on_start = self._get_path

    def _get_path(self, msrpdata):
        if msrpdata.code != 200:
            print "Failed to authenticate!"
            if msrpdata.comment:
                print msrpdata.comment
            self.protocol.transport.loseConnection()
            return
        sdp_path = list(reversed(msrpdata.headers["Use-Path"].decoded)) + [self.uri]
        print "Path to send in SDP:\n%s" % " ".join(str(uri) for uri in sdp_path)
        self.full_to_path = " ".join(str(uri) for uri in msrpdata.headers["Use-Path"].decoded) + " " + raw_input("Destination path: ")
        self.do_on_start = self._start_time

    def _start_time(self, msrpdata):
        filename = msrpdata.headers["Content-Disposition"].decoded[1]["filename"]
        print 'Receiving file "%s"' % filename
        self.outfile= open(msrpdata.headers["Content-Disposition"].decoded[1]["filename"], "wb")
        self.start_time = time.time()
        total = msrpdata.headers["Byte-Range"].decoded[2]
        if total:
            self.bytes_expected = total
        self.do_on_start = None
        self.do_on_data = self._receive_data
        self.do_on_end = self._quit

    def _receive_data(self, data):
        self.outfile.write(data)

    def _quit(self, continuation):
        if continuation == "$":
            duration = time.time() - self.start_time
            speed = self.byte_count / duration / 1024
            if self.byte_count == self.bytes_expected:
                print "File transfer completed successfully."
            else:
                print "File transfer aborted prematurely!"
            print "Received %d bytes in %.0f seconds, (%.2f kb/s)" % (self.byte_count, duration, speed)
            self.protocol.transport.loseConnection()

    def clientConnectionFailed(self, connector, err):
        print "Connection failed"
        print err.value
        reactor.callLater(0, reactor.stop)

    def clientConnectionLost(self, connector, err):
        print "Connection lost"
        print err.value
        reactor.callLater(0, reactor.stop)

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 4:
        print "Usage: %s user@domain [relay-hostname [relay-port]]" % sys.argv[0]
        print "If the hostname and port are not specified, the MSRP relay will be discovered"
        print "through the the _msrps._tcp.domain SRV record. If a hostname is specified but"
        print "no port, the default port of 2855 will be used."
    else:
        username, domain = sys.argv[1].split("@", 1)
        cred = X509Credentials(None, None)
        cred.verify_peer = False
        password = getpass()
        if len(sys.argv) == 2:
            factory = MSRPFileReceiverFactory(username, password, URI(domain, use_tls = True))
            connector = SRVConnector(reactor, "msrps", domain, factory, connectFuncName = "connectTLS", connectFuncArgs = [cred])
            connector.connect()
        else:
            relay_host = sys.argv[2]
            if len(sys.argv) == 4:
                relay_port = int(sys.argv[3])
            else:
                relay_port = 2855
            factory = MSRPFileReceiverFactory(username, password, URI(relay_host, port = relay_port, use_tls = True))
            reactor.connectTLS(relay_host, relay_port, factory, cred)
        reactor.run()
