#!/usr/bin/env python

import sys
sys.path.append(".")
sys.path.append("..")
import time
import os
from base64 import b64encode
from getpass import getpass

from twisted.names.srvconnect import SRVConnector
from twisted.internet.protocol import ClientFactory
from twisted.internet import reactor

from gnutls.interfaces.twisted import TLSContext, X509Credentials

from msrp.protocol import *
from msrp.digest import process_www_authenticate
from msrp.responses import *

rand_source = open("/dev/urandom")
BLOCK_SIZE = 64 * 1024

def generate_transaction_id():
    return b64encode(rand_source.read(12), "+-")

class MSRPFileSenderFactory(ClientFactory):
    protocol = MSRPProtocol

    def __init__(self, username, password, relay_uri, infile, filename):
        self.uri = URI("localhost", use_tls = True, port = 12345, session_id = b64encode(rand_source.read(12)))
        self.username = username
        self.password = password
        self.relay_uri = relay_uri
        self.infile = infile
        self.filename = filename
        self.byte_count = 0
        self.do_on_start = None
        self.do_on_data = None
        self.do_on_end = None
        self.start_time = None
        self.complete = False

    def get_peer(self, protocol):
        self.protocol = protocol
        reactor.callLater(0, self._send_auth1)
        return self

    def data_start(self, msrpdata):
        if self.do_on_start:
            self.do_on_start(msrpdata)

    def write_chunk(self, data):
        self.byte_count += len(data)
        print "received %d bytes, total %d" % (len(data), self.byte_count)
        if self.do_on_data:
            self.do_on_data(data)

    def data_end(self, continuation):
        if self.do_on_end:
            self.do_on_end(continuation)

    def connection_lost(self, reason):
        print "Connection lost!"
        if self.complete:
            duration = time.time() - self.start_time
            speed = self.file_size / duration / 1024
            print "Sent %d bytes in %.0f seconds, (%.2f kb/s)" % (self.file_size, duration, speed)
        else:
            print "File transfer was aborted prematurely."

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
        print 'Starting transmission of "%s"' % self.filename
        self.do_on_start = None
        self.infile.seek(0, 2)
        self.file_size = self.infile.tell()
        self.infile.seek(0, 0)
        msrpdata = MSRPData(generate_transaction_id(), method = "SEND")
        msrpdata.add_header(FromPathHeader([self.uri]))
        msrpdata.add_header(MSRPHeader("To-Path", self.full_to_path))
        msrpdata.add_header(MessageIDHeader("1"))
        msrpdata.add_header(ByteRangeHeader([1, self.file_size, self.file_size]))
        msrpdata.add_header(ContentTypeHeader("binary/octet-stream"))
        msrpdata.add_header(FailureReportHeader("no"))
        msrpdata.add_header(ContentDispositionHeader(["attachment", {"filename": self.filename}]))
        self.start_time = time.time()
        self.protocol.transport.write(msrpdata.encode_start())
        sent = 0
        for i in range(0, self.file_size, BLOCK_SIZE):
            print "sent %d of %d bytes" % (sent, self.file_size)
            sent += i
            data = self.infile.read(BLOCK_SIZE)
            self.protocol.transport.write(data)
        print "File transfer completed."
        self.complete = True
        self.protocol.transport.write(msrpdata.encode_end("$"))

    def clientConnectionFailed(self, connector, err):
        print "Connection failed"
        print err.value
        reactor.callLater(0, reactor.stop)

    def clientConnectionLost(self, connector, err):
        print "Connection lost"
        print err.value
        reactor.callLater(0, reactor.stop)

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 5:
        print "Usage: %s infile user@domain [relay-hostname [relay-port]]" % sys.argv[0]
        print "If the hostname and port are not specified, the MSRP relay will be discovered"
        print "through the the _msrps._tcp.domain SRV record. If a hostname is specified but"
        print "no port, the default port of 2855 will be used."
    else:
        filename = sys.argv[1]
        infile = open(filename, "rb")
        username, domain = sys.argv[2].split("@", 1)
        cred = X509Credentials(None, None)
        cred.verify_peer = False
        ctx = TLSContext(cred)
        password = getpass()
        if len(sys.argv) == 3:
            factory = MSRPFileSenderFactory(username, password, URI(domain, use_tls = True), infile, filename.split(os.path.sep)[-1])
            connector = SRVConnector(reactor, "msrps", domain, factory, connectFuncName="connectTLS", connectFuncArgs=[ctx])
            connector.connect()
        else:
            relay_host = sys.argv[3]
            if len(sys.argv) == 5:
                relay_port = int(sys.argv[4])
            else:
                relay_port = 2855
            factory = MSRPFileSenderFactory(username, password, URI(relay_host, port = relay_port, use_tls = True), infile, filename.split(os.path.sep)[-1])
            reactor.connectTLS(relay_host, relay_port, factory, ctx)
        reactor.run()
