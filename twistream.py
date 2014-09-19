# -*- coding: utf8 -*-

from tornado import iostream
import socket
from tornado.auth import TwitterMixin
from tornado import escape
import urllib
import tornado.httputil


def _parse_headers(data):
        data = escape.native_str(data.decode('latin1'))
        eol = data.find("\r\n")
        start_line = data[:eol]
        try:
            headers = tornado.httputil.HTTPHeaders.parse(data[eol:])
        except ValueError:
            # probably form split() if there was no ':' in the line
            raise tornado.httputil.HTTPInputError("Malformed HTTP headers: %r" %
                                          data[eol:100])
        return start_line, headers


class Stream(TwitterMixin):

    _OAUTH_VERSION = "1.0a"

    host = "stream.twitter.com"

    def __init__(self, auth, listener):
        self.auth = auth
        self.listener = listener
        self.headers = {}
        self.parameters = {}
        self.url = None
        self.stream = None
        self.closed = False

    def _oauth_consumer_token(self):
        return dict(
            key=self.auth["consumer_key"],
            secret=self.auth["consumer_secret"]
        )

    def open_twitter_stream(self):
        address_info = socket.getaddrinfo(self.host, 443,
                                          socket.AF_INET, socket.SOCK_STREAM,
                                          0, 0)
        af, sock_type, protocol = address_info[0][:3]
        socket_address = address_info[0][-1]
        sock = socket.socket(af, sock_type, protocol)
        self.stream = iostream.SSLIOStream(sock)
        self.stream.set_close_callback(self.on_close)
        self.stream.connect(socket_address, self._on_connect)

    def on_close(self):
        self.listener.on_close()

    def _on_connect(self):
        url = "https://%s%s" % (self.host, self.url)
        method = "POST" if 'Content-Type' in self.headers \
                           and self.headers.get("Content-Type") == "application/x-www-form-urlencoded" else "GET"
        parameters = self._oauth_request_parameters(url,
                                                    dict(key=self.auth["access_token"],
                                                         secret=self.auth["access_token_secret"]),
                                                    self.parameters,
                                                    method=method)
        headers = dict()
        headers["Host"] = self.host
        headers["User-Agent"] = "TwistStream"
        headers["Accept"] = "*/*"
        self.parameters.update(parameters)
        if method is "POST":
            headers["Content-Length"] = len(urllib.urlencode(self.parameters))
        else:
            self.url += "?%s" % (urllib.urlencode(self.parameters))
        headers.update(self.headers)

        request = ["%s %s HTTP/1.1" % (method, self.url)]
        for key, value in headers.iteritems():
            request.append("%s: %s" % (key, value))
        request = "\r\n".join(request) + "\r\n\r\n"
        if method == "POST":
            request += urllib.urlencode(self.parameters) + "\r\n\r\n"
        self.stream.write(str(request))
        self.stream.read_until("\r\n\r\n", self.on_headers)

    def on_headers(self, response):
        start_line, headers = _parse_headers(response)
        start_line = tornado.httputil.parse_response_start_line(start_line)
        self.listener.on_headers(start_line, headers)
        self.stream.read_until("\r\n", self.on_result)

    def on_result(self, data):
        self.listener.on_data(data)
        if not self.closed:
            self.stream.read_until("\r\n", self.on_result)

    def _start(self):
        self.open_twitter_stream()

    def close(self):
        self.closed = True
        self.stream.close()

    def filter(self, follow=None, track=None, locations=None,
               stall_warnings=False, languages=None, delimited=None, encoding='utf8'):
        self.headers['Content-Type'] = "application/x-www-form-urlencoded"
        self.url = '/1.1/statuses/filter.json'
        if follow:
            encoded_follow = [s.encode(encoding) for s in follow]
            self.parameters['follow'] = ','.join(encoded_follow)
        if track:
            encoded_track = [s.encode(encoding) for s in track]
            self.parameters['track'] = ','.join(encoded_track)
        if locations and len(locations) > 0:
            if len(locations) % 4 != 0:
                raise Exception("Wrong number of locations points, "
                                 "it has to be a multiple of 4")
            self.parameters['locations'] = ','.join(['%.4f' % l for l in locations])
        if stall_warnings:
            self.parameters['stall_warnings'] = stall_warnings
        if languages:
            self.parameters['language'] = ','.join(map(str, languages))
        if delimited:
            self.parameters["parameters"] = "length"
        self._start()

    def user_stream(self, stall_warnings=False, _with=None, replies=None,
            track=None, locations=None, delimited=None,
            follow=None, stringify_friend_ids=None,  encoding='utf8'):

        self.url = '/1.1/user.json'
        self.host = 'userstream.twitter.com'

        if stall_warnings:
            self.parameters['stall_warnings'] = stall_warnings
        if _with:
            self.parameters['with'] = _with
        if replies:
            self.parameters['replies'] = replies
        if locations and len(locations) > 0:
            if len(locations) % 4 != 0:
                raise Exception("Wrong number of locations points, "
                                 "it has to be a multiple of 4")
            self.parameters['locations'] = ','.join(['%.2f' % l for l in locations])
        if track:
            self.parameters['track'] = ','.join([s.encode(encoding) for s in track])
        if follow:
            self.parameters['follow'] = ','.join([s.encode(encoding) for s in follow])
        if stringify_friend_ids:
            self.parameters['stringify_friend_ids'] = "1"
        if delimited:
            self.parameters["parameters"] = "length"
        self._start()

    def fire_hose(self, count=None, delimited=None):
        self.url = '/1.1/statuses/firehose.json'
        if count:
            self.parameters["count"] = count
        if delimited:
            self.parameters["parameters"] = "length"

        self._start()

    def sample(self, language=None, delimited=None):
        self.url = '/1.1/statuses/sample.json'
        if language:
            self.parameters['language'] = language

        if delimited:
            self.parameters["parameters"] = "length"

        self._start()
