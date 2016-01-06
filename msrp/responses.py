
from msrp.protocol import *

def generate_report(code, forwarding_data, reason=None):
    from_data = forwarding_data.msrpdata_received
    report = MSRPData(generate_transaction_id(), method = "REPORT")
    report.add_header(ToPathHeader(from_data.headers["From-Path"].encoded))
    report.add_header(FromPathHeader([from_data.headers["To-Path"].decoded[0]]))
    report.add_header(StatusHeader((code, reason)))
    report.add_header(MessageIDHeader(from_data.headers["Message-ID"].encoded))
    start, end, total = forwarding_data.msrpdata_forward.headers["Byte-Range"].decoded
    if forwarding_data.bytes_received:
        end = start + forwarding_data.bytes_received - 1
        report.add_header(ByteRangeHeader([start, end, total]))
    return report

def exception_from_data(data):
    try:
        response_exception = _response_exceptions[data.code]
    except KeyError:
        response = ResponseExceptionBase(data)
        response.code = data.code
        return response
    class ResponseExceptionWrapper(response_exception):
        def __init__(self, data):
            ResponseExceptionBase.__init__(self, data)
    return ResponseExceptionWrapper(data)

class ResponseExceptionBase(MSRPError):

    def __init__(self, data):
        self.data = data

    def __str__(self):
        if self.data.comment:
            return "%03d %s" % (self.data.code, self.data.comment)
        else:
            return "%03d" % self.data.code

class ResponseException(ResponseExceptionBase):

    def __init__(self, code, request_data, comment = None, headers = []):
        data = MSRPData(request_data.transaction_id, code = code, comment = comment)
        for header in headers:
            data.headers[header.name] = header
        data.add_header(ToPathHeader([request_data.headers["From-Path"].decoded[0]]))
        data.add_header(FromPathHeader([request_data.headers["To-Path"].decoded[0]]))
        ResponseExceptionBase.__init__(self, data)

class ResponseOK(ResponseException):
    code = 200

    def __init__(self, request_data, headers = []):
        ResponseException.__init__(self, self.code, request_data, "OK", headers)

class ResponseUnintelligible(ResponseException):
    code = 400

    def __init__(self, request_data, comment = None, headers = []):
        if comment:
            ResponseException.__init__(self, self.code, request_data, "Request was unintelligible, please try again (%s)" % comment, headers)
        else:
            ResponseException.__init__(self, self.code, request_data, "Request was unintelligible, please try again", headers)

class ResponseUnauthenticated(ResponseException):
    code = 401

    def __init__(self, request_data, headers = []):
        ResponseException.__init__(self, self.code, request_data, "Unauthenticated", headers)

class ResponseUnauthorized(ResponseException):
    code = 403

    def __init__(self, request_data, comment = None, headers = []):
        if comment is None:
            ResponseException.__init__(self, self.code, request_data, "Unauthorized to use this relay", headers)
        else:
            ResponseException.__init__(self, self.code, request_data, "Unauthorized: %s" % comment, headers)

class ResponseDownstreamTimeout(ResponseException):
    code = 408

    def __init__(self, request_data, headers = []):
        ResponseException.__init__(self, self.code, request_data, "Downstream transaction timed out", headers)

class ResponseAbort(ResponseException):
    code = 413

    def __init__(self, request_data, headers = []):
        ResponseException.__init__(self, self.code, request_data, "Please abort the message you are sending", headers)

class ResponseUnknownMediaType(ResponseException):
    code = 415

    def __init__(self, request_data, content_type = None, headers = []):
        ResponseException.__init__(self, self.code, request_data, "Unknown content type: %s" % content_type, headers)

class ResponseOutOfBounds(ResponseException):
    code = 423

    def __init__(self, request_data, parameter = None, headers = []):
        if parameter:
            ResponseException.__init__(self, self.code, request_data, "Parameter out of bounds: %s" % parameter, headers)
        else:
            ResponseException.__init__(self, self.code, request_data, "Parameter out of bounds", headers)

class ResponseNoSession(ResponseException):
    code = 481

    def __init__(self, request_data, comment = None, headers = []):
        if comment is None:
            ResponseException.__init__(self, self.code, request_data, "Indicated session does not exist, please terminate", headers)
        else:
            ResponseException.__init__(self, self.code, request_data, "Indicated session does not exist, please terminate: %s" % comment, headers)

class ResponseUnknownMethod(ResponseException):
    code = 501

    def __init__(self, request_data, headers = []):
        ResponseException.__init__(self, self.code, request_data, "Unknown method: %s" % request_data.method, headers)

class ResponseSessionTaken(ResponseException):
    code = 506

    def __init__(self, request_data, headers = []):
        ResponseException.__init__(self, self.code, request_data, "This session is already bound to another network connection, stop sending messages", headers)

_response_exceptions = dict((eval(cls_name).code,eval(cls_name)) for cls_name in globals() if cls_name.startswith("Response") and hasattr(eval(cls_name), "code"))
