# -*- coding: utf8 -*-

import os, sys, configparser, yara
import logging, logging.handlers
import hashlib, json, binascii

class YaraScanner():
    def __init__(self):
        self.maindir = os.path.dirname(os.path.abspath(__file__))
        self.log_path = os.path.join(self.maindir, 'yaraicap.log')
        self.config_path = os.path.join(self.maindir, 'config.ini')
        self.config = configparser.ConfigParser()
        self.config.read(self.config_path)
        self.initLogging()
        self.initYara()

    def initLogging(self):
        logging.captureWarnings(True)
        self.logger = logging.getLogger('YaraICAP')
        self.logger.setLevel(logging.DEBUG)

        # log file header
        fileHandler = logging.handlers.RotatingFileHandler(self.log_path, maxBytes=2000000, backupCount=5)
        formatter = logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] %(message)s')
        fileHandler.setFormatter(formatter)
        self.logger.addHandler(fileHandler)

        # log console handler 
        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(formatter)
        self.logger.addHandler(consoleHandler)

    def initYara(self):
        content_rules = self.config.get('config', 'content_rules')
        url_rules = self.config.get('config', 'url_rules')
        if not os.path.isfile(content_rules):
            self.logger.error('Content YARA rules not found')
            exit()

        if not os.path.isfile(url_rules):
            self.logger.error('URL YARA rules not found')
            exit()

        self.cyara = yara.compile(content_rules)
        self.uyara = yara.compile(url_rules)

    def SaveContent(self, chash, content, request_header, response_header, sig):
        writepath = "{path}/{hash}.json".format(path=self.config.get('config', 'content_dir'), hash=chash)
        if not os.path.isfile(writepath):
            data = {}
            data['rules'] = ','.join(str(x) for x in sig).split(',')
            data['request_header'] = request_header
            data['response_header'] = response_header
            data['content'] = binascii.hexlify(content)
            f = open(writepath, 'w')
            f.write(json.dumps(data, indent=4, sort_keys=True))
            f.close()

    def Scan(self, content, request, request_header, response_header, clientip):
        if self.config.getboolean('config', 'scan_url'):
            self.__ScanUrl(content, request, request_header, response_header, clientip)

        self.__ScanContent(content, request, request_header, response_header, clientip)

    def __ScanUrl(self, content, request, request_header, response_header, clientip):
        url = str(request[1])
        murl = self.uyara.match(data=url)
        murl_total = len(murl)
        if murl_total > 0:
            contentmd5 = hashlib.md5(url).hexdigest()
            self.SaveContent(contentmd5, content, request_header, response_header, murl)
            self.logger.info("[URL][{hash}][{rules}] {clientip} - {url}".format(hash=contentmd5, clientip=str(clientip[0]), url=url, rules=','.join(str(x) for x in murl)));

    def __ScanContent(self, content, request, request_header, response_header, clientip):
        url = str(request[1])
        mcontent = self.cyara.match(data=content)
        mcontent_total = len(mcontent)
        if mcontent_total > 0:
            contentmd5 = hashlib.md5(content).hexdigest()
            self.SaveContent(contentmd5, content, request_header, response_header, mcontent)
            self.logger.info("[Content][{hash}][{rules}] {clientip} - {url}".format(hash=contentmd5, clientip=str(clientip[0]), url=url, rules=','.join(str(x) for x in mcontent)));


if __name__ == '__main__':
    pass
