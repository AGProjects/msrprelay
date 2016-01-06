
from base64 import b64encode, b64decode
from hashlib import md5
from os import urandom
from time import time

class LoginFailed(Exception):
    pass

def calc_ha1(**parameters):
    ha1_text = "%(username)s:%(realm)s:%(password)s" % parameters
    return md5(ha1_text).hexdigest()

def calc_ha2_response(**parameters):
    ha2_text = "%(method)s:%(uri)s" % parameters
    return md5(ha2_text).hexdigest()

def calc_ha2_rspauth(**parameters):
    ha2_text = ":%(uri)s" % parameters
    return md5(ha2_text).hexdigest()

def calc_hash(**parameters):
    hash_text = "%(ha1)s:%(nonce)s:%(nc)s:%(cnonce)s:auth:%(ha2)s" % parameters
    return md5(hash_text).hexdigest()

def calc_responses(**parameters):
    if parameters.has_key("ha1"):
        ha1 = parameters.pop("ha1")
    else:
        ha1 = calc_ha1(**parameters)
    ha2_response = calc_ha2_response(**parameters)
    ha2_rspauth = calc_ha2_rspauth(**parameters)
    response = calc_hash(ha1 = ha1, ha2 = ha2_response, **parameters)
    rspauth = calc_hash(ha1 = ha1, ha2 = ha2_rspauth, **parameters)
    return response, rspauth

def process_www_authenticate(username, password, method, uri, **parameters):
    nc = "00000001"
    cnonce = urandom(16).encode("hex")
    parameters["username"] = username
    parameters["password"] = password
    parameters["method"] = method
    parameters["uri"] = uri
    response, rsp_auth = calc_responses(nc = nc, cnonce = cnonce, **parameters)
    authorization = {}
    authorization["username"] = username
    authorization["realm"] = parameters["realm"]
    authorization["nonce"] = parameters["nonce"]
    authorization["qop"] = "auth"
    authorization["nc"] = nc
    authorization["cnonce"] = cnonce
    authorization["response"] = response
    authorization["opaque"] = parameters["opaque"]
    return authorization, rsp_auth

class AuthChallenger(object):

    def __init__(self, expire_time):
        self.expire_time = expire_time
        self.key = urandom(16)

    def generate_www_authenticate(self, realm, peer_ip):
        www_authenticate = {}
        www_authenticate["realm"] = realm
        www_authenticate["qop"] = "auth"
        nonce = urandom(16) + "%.3f:%s" % (time(), peer_ip)
        www_authenticate["nonce"] = b64encode(nonce)
        opaque = md5(nonce + self.key)
        www_authenticate["opaque"] = opaque.hexdigest()
        return www_authenticate

    def process_authorization_ha1(self, ha1, method, uri, peer_ip, **parameters):
        parameters["method"] = method
        parameters["uri"] = uri
        try:
            nonce = parameters["nonce"]
            opaque = parameters["opaque"]
            response = parameters["response"]
        except IndexError, e:
            raise LoginFailed("Parameter not present: %s", e.message)
        try:
            expected_response, rspauth = calc_responses(ha1 = ha1, **parameters)
        except:
            raise
            #raise LoginFailed("Parameters error")
        if response != expected_response:
            raise LoginFailed("Incorrect password")
        try:
            nonce_dec = b64decode(nonce)
            issued, nonce_ip = nonce_dec[16:].split(":", 1)
            issued = float(issued)
        except:
            raise LoginFailed("Could not decode nonce")
        if nonce_ip != peer_ip:
            raise LoginFailed("This challenge was not issued to you")
        expected_opaque = md5(nonce_dec + self.key).hexdigest()
        if opaque != expected_opaque:
            raise LoginFailed("This nonce/opaque combination was not issued by me")
        if issued + self.expire_time < time():
            raise LoginFailed("This challenge has expired")
        authentication_info = {}
        authentication_info["qop"] = "auth"
        authentication_info["cnonce"] = parameters["cnonce"]
        authentication_info["nc"] = parameters["nc"]
        authentication_info["rspauth"] = rspauth
        return authentication_info

    def process_authorization_password(self, password, method, uri, peer_ip, **parameters):
        ha1 = calc_ha1(password = password, **parameters)
        return self.process_authorization_ha1(ha1, method, uri, peer_ip, **parameters)
