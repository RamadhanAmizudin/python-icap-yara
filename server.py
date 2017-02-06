# -*- coding: utf8 -*-

import os, datetime, string, sys
import time, threading
import logging, logging.handlers
import socket
from yarascanner import *
from icapserver import *

def dump(obj):
    for attr in dir(obj):
        print "obj.%s = %s" % (attr, getattr(obj, attr))

yara = YaraScanner()

class YaraICAPHandler(BaseICAPRequestHandler):

    def yara_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header('Methods', 'RESPMOD')
        self.set_icap_header('Service', 'ICAP Server' + ' ' + self._server_version)
        self.set_icap_header('Options-TTL', '3600')
        self.set_icap_header('Preview', '0')
        self.send_headers(False)

    def yara_REQMOD(self):
        self.no_adaptation_required()

    def yara_RESPMOD(self):
        self.set_icap_response(200)
        self.set_enc_status(' '.join(self.enc_res_status))
        for h in self.enc_res_headers:
            for v in self.enc_res_headers[h]:
                self.set_enc_header(h, v)

        if not self.has_body:
            self.send_headers(False)
            return

        self.send_headers(True)
        content = ''
        while True:
            chunk = self.read_chunk()
            self.send_chunk(chunk)
            content += chunk
            if chunk == '':
                break

        yara.Scan(content, self.enc_req, self.enc_req_headers, self.enc_res_headers, self.headers['x-client-ip'])

class YaraICAPServer():

    def __init__(self, addr='', port=1344):
        self.addr = addr
        self.port = port

    def start(self):
        self.server = ICAPServer((self.addr, self.port), YaraICAPHandler)
        self.server.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        return True

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        return True


try:
    server = YaraICAPServer()
    server.start()
    print 'Use Control-C to exit'
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    server.stop()
    print "Finished"
