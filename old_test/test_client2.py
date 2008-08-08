from base64 import b64encode

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

class MSRPTestClientFactory(ClientFactory):
    protocol = MSRPProtocol

    def __init__(self, host, port):
        self.uri = URI(host, use_tls = True, port = port, session_id = b64encode(rand_source.read(12)))
        self.relay_uri = URI("ws1.dns-hosting.info", use_tls = True, port = 10000)
        self.do_on_start = None
        self.do_on_data = None

    def get_peer(self, protocol):
        self.protocol = protocol
        reactor.callLater(0, self._send_auth1)
        return self

    def data_start(self, msrpdata):
        print "RECEIVED %s" % str(msrpdata)
        print "HEADERS:\n%s" % "\n".join("%s: %s" % (hname, hval.encoded) for hname, hval in msrpdata.headers.iteritems())
        if self.do_on_start:
            self.do_on_start(msrpdata)

    def write_chunk(self, data):
        print "GOT DATA"
        if self.do_on_data:
            self.do_on_data(data)

    def data_end(self, msrpdata):
        print "GOT END"

    def connection_lost(self, reason):
        pass

    def _send_auth1(self):
        msrpdata = MSRPData(generate_transaction_id(), method = "AUTH")
        msrpdata.add_header(ToPathHeader([self.relay_uri]))
        msrpdata.add_header(FromPathHeader([self.uri]))
        print "SENDING:\n\n%s" % msrpdata.encode()
        self.protocol.transport.write(msrpdata.encode())
        self.do_on_start = self._send_auth2

    def _send_auth2(self, msrpdata):
        auth, rsp_auth = process_www_authenticate("user2", "pass2", "AUTH", str(self.relay_uri), **msrpdata.headers["WWW-Authenticate"].decoded)
        msrpdata = MSRPData(generate_transaction_id(), method = "AUTH")
        msrpdata.add_header(ToPathHeader([self.relay_uri]))
        msrpdata.add_header(FromPathHeader([self.uri]))
        msrpdata.add_header(AuthorizationHeader(auth))
        print "SENDING:\n\n%s" % msrpdata.encode()
        self.protocol.transport.write(msrpdata.encode())
        self.do_on_start = self._get_path

    def _get_path(self, msrpdata):
        sdp_path = list(reversed(msrpdata.headers["Use-Path"].decoded)) + [self.uri]
        print "Path to send in SDP: %s" % " ".join(str(uri) for uri in sdp_path)
        self.full_to_path = " ".join(str(uri) for uri in msrpdata.headers["Use-Path"].decoded) + " " + raw_input("Destination path: ")
        self.do_on_start = self._send_ok
        self.do_on_data = self._receive_msg

    def _send_ok(self, msrpdata):
        ok = MSRPData(msrpdata.transaction_id, code=200)
        ok.add_header(FromPathHeader([self.uri]))
        ok.add_header(ToPathHeader(self.full_to_path))
        self.protocol.transport.write(ok.encode())
        self.do_on_start = None

    def _receive_msg(self, data):
        print "Got (part of) message: %s" % data

    def clientConnectionFailed(self, connector, err):
        print err.value

    def clientConnectionLost(self, connector, err):
        print err.value

ca = X509Certificate(open("../certs/ca-cert.pem").read())
cred = X509Credentials(None, None, [ca])
cred.verify_peer = True

factory = MSRPTestClientFactory("node03.dns-hosting.info", 12345)
reactor.connectTLS("ws1.dns-hosting.info", 10000, factory, cred, server_name = "dns-hosting.info")
reactor.run()

