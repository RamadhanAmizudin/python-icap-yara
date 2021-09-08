# -*- coding: utf8 -*-

import os, datetime, string, sys
import time, threading
import logging, logging.handlers
import socket, socketserver
from yarascanner import *
from icapserver import *

def dump(obj):
    for attr in dir(obj):
        print("obj.%s = %s") % (attr, getattr(obj, attr))

yara = YaraScanner()

class ThreadingSimpleServer(socketserver.ThreadingMixIn, ICAPServer):
    pass

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

try:
    print('Use Control-C to exit')
    server = ThreadingSimpleServer(('127.0.0.1', 1344), YaraICAPHandler)
    server.serve_forever()
except KeyboardInterrupt:
    server.shutdown()
    server.server_close()
    print("Finished")
