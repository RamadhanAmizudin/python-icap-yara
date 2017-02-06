#-*-: coding: utf-8
"""
# ===================================================================================================================== #
#  Implements an ICAP server framework                                                                                  #
#  For the ICAP specification, see RFC 3507                                                                             #
# ===================================================================================================================== #
# Project Name: ICAP Server framework
# Version: 1.2
# Author: Nikolay Ivanov
# Author Email: peoplecantfly@gmail.com
# License: MIT License
# Project URL: https://github.com/Peoplecantfly/icapserver
"""

import sys
import time
import random
import socket
import string
import logging
import urlparse
import SocketServer

__version__ = "1.2"

__all__ = ['ICAPServer', 'BaseICAPRequestHandler', 'ICAPError']

LOG = logging.getLogger(__name__)
level = logging.INFO
logging.basicConfig(level=level, format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s", filename="")

class ICAPError(Exception):
	""" 
	Signals a protocol error.
	"""
	def __init__(self, code=500, message=None):
		if message is None:
			short, long = BaseICAPRequestHandler._responses[code]
			message = short

		super(ICAPError, self).__init__(message)
		self.code = code
		msg = 'Code: %d Message: %s' % (code, message)
		LOG.error(msg)

class ICAPServer(SocketServer.TCPServer):
	""" 
	ICAP Server
	This is a simple TCPServer, that allows address reuse.
	"""
	allow_reuse_address = 1

class BaseICAPRequestHandler(SocketServer.StreamRequestHandler):
	""" 
	ICAP request handler base class.
	You have to subclass it and provide methods for each service
	endpoint. Every endpoint MUST have an _OPTION method,
	and _REQMOD or a _RESPMOD method or both.
	"""
	# The version of the Python.
	_sys_version = "Python/" + sys.version.split()[0]

	# The version of the ICAP protocol.
	_protocol_version = "ICAP/1.0"

	# The server software version.
	_server_version = "ICAP/" + __version__

	# Table mapping response codes to messages; entries have the
	# form {code: (shortmessage, longmessage)}.
	# See RFC 2616 and RFC 3507
	_responses = {
		100: ('Continue', 'Request received, please continue'),
		101: ('Switching Protocols', 'Switching to new protocol; obey Upgrade header'),

		200: ('OK', 'Request fulfilled, document follows'),
		201: ('Created', 'Document created, URL follows'),
		202: ('Accepted', 'Request accepted, processing continues off-line'),
		203: ('Non-Authoritative Information', 'Request fulfilled from cache'),
		204: ('No Content', 'Request fulfilled, nothing follows'),
		205: ('Reset Content', 'Clear input form for further input.'),
		206: ('Partial Content', 'Partial content follows.'),

		300: ('Multiple Choices', 'Object has several resources -- see URI list'),
		301: ('Moved Permanently', 'Object moved permanently -- see URI list'),
		302: ('Found', 'Object moved temporarily -- see URI list'),
		303: ('See Other', 'Object moved -- see Method and URL list'),
		304: ('Not Modified', 'Document has not changed since given time'),
		305: ('Use Proxy', 'You must use proxy specified in Location to access this resource.'),
		307: ('Temporary Redirect', 'Object moved temporarily -- see URI list'),

		400: ('Bad Request', 'Bad request syntax or unsupported method'),
		401: ('Unauthorized', 'No permission - see authorization schemes'),
		402: ('Payment Required', 'No payment - see charging schemes'),
		403: ('Forbidden', 'Request forbidden - authorization will not help'),
		404: ('Not Found', 'Nothing matches the given URI'),
		405: ('Method Not Allowed', 'Specified method is invalid for this resource.'),
		406: ('Not Acceptable', 'URI not available in preferred format.'),
		407: ('Proxy Authentication Required', 'You must authenticate with this proxy before proceeding.'),
		408: ('Request Timeout', 'Request timed out; try again later.'),
		409: ('Conflict', 'Request conflict.'),
		410: ('Gone', 'URI no longer exists and has been permanently removed.'),
		411: ('Length Required', 'Client must specify Content-Length.'),
		412: ('Precondition Failed', 'Precondition in headers is false.'),
		413: ('Request Entity Too Large', 'Entity is too large.'),
		414: ('Request-URI Too Long', 'URI is too long.'),
		415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
		416: ('Requested Range Not Satisfiable', 'Cannot satisfy request range.'),
		417: ('Expectation Failed', 'Expected condition could not be satisfied.'),
		451: ('451 Unavailable For Legal Reasons', 'Resource access is denied for legal reasons, \
													e.g. censorship or government-mandated blocked access.'),

		500: ('Internal Server Error', 'Server got itself in trouble'),
		501: ('Not Implemented', 'Server does not support this operation'),
		502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
		503: ('Service Unavailable', 'The server cannot process the request due to a high load'),
		504: ('Gateway Timeout', 'The gateway server did not receive a timely response'),
		505: ('Protocol Version Not Supported', 'Cannot fulfill request.'),
	}

	_weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

	_monthname = [None,
				'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
				'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

	def _read_status(self):
		""" 
		Read a HTTP or ICAP status line from input stream.
		"""
		status = self.rfile.readline().strip().split(' ', 2)
		LOG.debug(status)
		return status

	def _read_request(self):
		""" Read a HTTP or ICAP request line from input stream.
		"""
		request = self.rfile.readline().strip().split(' ', 2)
		LOG.debug(request)
		return request

	def _read_headers(self):
		""" 
		Read a sequence of header lines.
		"""

		headers = {}
		while True:
			line = self.rfile.readline().strip()
			if line == '':
				break
			k, v = line.split(':', 1)
			headers[k.lower()] = headers.get(k.lower(), []) + [v.strip()]
		LOG.debug(headers)
		return headers

	def read_chunk(self):
		""" 
		Read a ICAP chunk
		Also handles the ieof chunk extension defined by the ICAP
		protocol by setting the ieof variable to True. It returns an
		empty line if the last chunk is read. Reading after the last
		chunks will return empty strings.
		"""

		# Don't try to read when there's no body
		if not self.has_body or self.eob:
			self.eob = True
			return ''

		line = self.rfile.readline()
		if line == '':
			# Connection was probably closed
			self.eob = True
			return ''

		line = line.strip()

		arr = line.split(';', 1)

		chunk_size = 0
		try:
			chunk_size = int(arr[0], 16)
		except ValueError:
			raise ICAPError(400, 'Protocol error, could not read chunk')

		# Look for ieof chunk extension
		if len(arr) > 1 and arr[1].strip() == 'ieof':
			self.ieof = True

		value = self.rfile.read(chunk_size)
		self.rfile.read(2)

		if value == '':
			self.eob = True

		return value

	def send_chunk(self, data):
		""" 
		Send a chunk of data
		When finished writing, an empty chunk with data='' must be written.
		"""

		l = hex(len(data))[2:]
		self.wfile.write(l + '\r\n' + data + '\r\n')

	def cont(self):
		""" 
		Send a 100 continue reply
		Useful when the client sends a preview request, and we have
		to read the entire message body. After this command, read_chunk
		can safely be called again.
		"""

		if self.ieof:
			raise ICAPError(500, 'Tried to continue on ieof condition')

		self.wfile.write(self._protocol_version + ' ' + '100 Continue\r\n\r\n')

		self.eob = False

	def set_enc_status(self, status):
		""" 
		Set encapsulated status in response
		ICAP responses can only contain one encapsulated header section.
		Such section is either an encapsulated HTTP request, or a
		response. This method can be called to set encapsulated HTTP
		response's status line.
		"""

		self.enc_status = status
		msg = 'Encapsulated status: %s' % status
		LOG.debug(msg)

	def set_enc_request(self, request):
		""" 
		Set encapsulated request line in response.
		ICAP responses can only contain one encapsulated header section.
		Such section is either an encapsulated HTTP request, or a
		response. This method can be called to set encapsulated HTTP
		request's request line.
		"""

		self.enc_request = request
		msg = 'Encapsulated request: %s' % request
		LOG.debug(msg)

	def set_enc_header(self, header, value):
		""" 
		Set an encapsulated header to the given value.
		Multiple sets will cause the header to be sent multiple times.
		"""
		if not isinstance(header, str):
			raise ICAPError(500, 'Header must be a string, not %s.' % type(header))

		if not isinstance(value, str):
			raise ICAPError(500, 'Header value must be a string, not %s.' % type(value))

		self.enc_headers[header] = self.enc_headers.get(header, []) + [value]
		msg = 'Encapsulated header: %s : %s' % (header, value)
		LOG.debug(msg)

	def update_enc_header(self, header, value):
		"""
		Update an encapsulated header to the given value
		"""

		if not isinstance(header, str):
			raise ICAPError(500, 'Header must be a string, not %s.' % type(header))

		if not isinstance(value, str):
			raise ICAPError(500, 'Header value must be a string, not %s.' % type(value))

		for k in self.enc_headers:
			if k.lower() == header.lower():
				self.enc_headers[k] = [value]
				msg = 'Encapsulated header %s updated to the new value %s' % (header, value)
				LOG.debug(msg)
				return

		msg = 'Encapsulated header %s not found' % header
		LOG.error(msg)

	def delete_enc_header(self, header):
		"""
		Delete an encapsulated header.
		"""

		if not isinstance(header, str):
			raise ICAPError(500, 'Header must be a string, not %s.' % type(header))

		for k in self.enc_headers:
			if k.lower() == header.lower():
				del self.enc_headers[k]
				msg = 'Encapsulated header %s deleted' % header
				LOG.debug(msg)
				return

		msg = 'Encapsulated header %s not found' % header
		LOG.error(msg)

	def set_icap_response(self, code, message=None):
		""" 
		Sets the ICAP response's status line and response code.
		"""

		try:
			short, long = self._responses[code]
		except KeyError:
			short, long = '???', '???'
		if message is None:
			message = short

		if not isinstance(message, str):
			raise ICAPError(500)

		self.icap_response = self._protocol_version + ' ' + str(code) + ' ' + message
		self.icap_response_code = code
		msg = 'ICAP response: %s' % self.icap_response
		LOG.debug(msg)

	def set_icap_header(self, header, value):
		""" 
		Set an ICAP header to the given value
		Multiple sets will cause the header to be sent multiple times.
		"""

		if not isinstance(header, str):
			raise ICAPError(500, 'Header must be a string, not %s.' % type(header))

		if not isinstance(value, str):
			raise ICAPError(500, 'Header value must be a string, not %s.' % type(value))

		self.icap_headers[header] = self.icap_headers.get(header, []) + [value]
		msg = 'ICAP header: %s : %s' % (header, value)
		LOG.debug(msg)

	def update_icap_header(self, header, value):
		"""
		Update an ICAP header to the given value
		"""

		if not isinstance(header, str):
			raise ICAPError(500, 'Header must be a string, not %s.' % type(header))

		if not isinstance(value, str):
			raise ICAPError(500, 'Header value must be a string, not %s.' % type(value))

		for k in self.icap_headers:
			if k.lower() == header.lower():
				self.icap_headers[k] = [value]
				msg = 'ICAP header %s updated to the new value %s' % (header, value)
				LOG.debug(msg)
				return

		msg = 'ICAP header %s not found' % header
		LOG.error(msg)

	def delete_icap_header(self, header):
		"""
		Delete an existing ICAP header.
		"""

		if not isinstance(header, str):
			raise ICAPError(500, 'Header must be a string, not %s.' % type(header))

		for k in self.icap_headers:
			if k.lower() == header.lower():
				del self.icap_headers[k]
				msg = 'ICAP header %s deleted' % header
				LOG.debug(msg)
				return

		msg = 'ICAP header %s not found' % header
		LOG.error(msg)

	def send_headers(self, has_body=False):
		""" 
		Send ICAP and encapsulated headers.
		Assembles the Encapsulated header, so it's need the information
		of wether an encapsulated message body is present.
		"""

		enc_header = None
		enc_req_stat = ''
		if self.enc_request != None:
			enc_header = 'req-hdr=0'
			enc_body = 'req-body='
			enc_req_stat = self.enc_request + '\r\n'
		elif self.enc_status != None:
			enc_header = 'res-hdr=0'
			enc_body = 'res-body='
			enc_req_stat = self.enc_status + '\r\n'

		if not has_body:
			enc_body = 'null-body='

		if not self.icap_headers.has_key('ISTag'):
			self.set_icap_header('ISTag', ''.join([random.choice(string.ascii_uppercase \
																+ string.digits) for x in xrange(32)]))

		if not self.icap_headers.has_key('Date'):
			self.set_icap_header('Date', self.date_time_string())

		if not self.icap_headers.has_key('Server'):
			self.set_icap_header('Server', self.version_string())

		enc_header_str = enc_req_stat
		for k in self.enc_headers:
			for v in self.enc_headers[k]:
				enc_header_str += k + ': ' + v + '\r\n'
		if enc_header_str != '':
			enc_header_str += '\r\n'

		body_offset = len(enc_header_str)

		if enc_header:
			enc = enc_header + ', ' + enc_body + str(body_offset)
			self.set_icap_header('Encapsulated', enc)

		icap_header_str = ''
		for k in self.icap_headers:
			for v in self.icap_headers[k]:
				icap_header_str += k + ': ' + v + '\r\n'
				if k.lower() == 'connection' and v.lower() == 'close':
					self.close_connection = True
				if k.lower() == 'connection' and v.lower() == 'keep-alive':
					self.close_connection = False
		icap_header_str += '\r\n'

		self.wfile.write(self.icap_response + '\r\n' + icap_header_str + enc_header_str)

	def parse_request(self):
		""" 
		Parse a request (internal).
		The request should be stored in self.raw_requestline; the results
		are in self.command, self.request_uri, self.request_version and self.headers.
		Return True for success, False for failure; on failure, an error is sent back.
		"""

		self.command = None
		self.request_version = version = self._protocol_version

		# Default behavior is to leave connection open
		self.close_connection = False

		requestline = self.raw_requestline.rstrip('\r\n')
		self.requestline = requestline

		words = requestline.split()
		if len(words) != 3:
			raise ICAPError(400, "Bad request syntax (%r)" % requestline)

		command, request_uri, version = words

		if version[:5] != 'ICAP/':
			raise ICAPError(400, "Bad request protocol, only accepting ICAP")

		if command not in  ['OPTIONS', 'REQMOD', 'RESPMOD']:
			raise ICAPError(501, "command %r is not implemented" % command)

		try:
			base_version_number = version.split('/', 1)[1]
			version_number = base_version_number.split(".")
			# RFC 2145 section 3.1 says there can be only one "." and
			#   - major and minor numbers MUST be treated as
			#      separate integers;
			#   - ICAP/2.4 is a lower version than ICAP/2.13, which in
			#      turn is lower than ICAP/12.3;
			#   - Leading zeros MUST be ignored by recipients.
			if len(version_number) != 2:
				raise ValueError
			version_number = int(version_number[0]), int(version_number[1])
		except (ValueError, IndexError):
			raise ICAPError(400, "Bad request version (%r)" % version)

		if version_number != (1, 0):
			raise ICAPError(505, "Invalid ICAP Version (%s)" % base_version_number)

		self.command, self.request_uri, self.request_version = command, request_uri, version

		# Examine the headers and look for a Connection directive
		self.headers = self._read_headers()

		conntype = self.headers.get('connection', [''])[0]
		if conntype.lower() == 'close':
			self.close_connection = True

		self.encapsulated = {}
		if self.command in ['RESPMOD', 'REQMOD']:
			_encapsulated = self.headers.get('encapsulated', [''])[0].split(',')
			if not _encapsulated:
				raise ICAPError(500, "Encapsulated is empty.")
			for enc in _encapsulated:
				try:
					k, v = enc.strip().split('=')
				except:
					raise ICAPError(500, "Encapsulated is malformed.")
				self.encapsulated[k] = int(v)

		self.preview = self.headers.get('preview', [None])[0]
		self.allow = [x.strip() for x in self.headers.get('allow', [''])[0].split(',')]

		if self.command == 'REQMOD':
			if self.encapsulated.has_key('req-hdr'):
				self.enc_req = self._read_request()
				self.enc_req_headers = self._read_headers()
			if self.encapsulated.has_key('req-body'):
				self.has_body = True
		elif self.command == 'RESPMOD':
			if self.encapsulated.has_key('req-hdr'):
				self.enc_req = self._read_request()
				self.enc_req_headers = self._read_headers()
			if self.encapsulated.has_key('res-hdr'):
				self.enc_res_status = self._read_status()
				self.enc_res_headers = self._read_headers()
			if self.encapsulated.has_key('res-body'):
				self.has_body = True
		# Else: OPTIONS. No encapsulation.

		# Parse service name
		self.servicename = urlparse.urlparse(self.request_uri)[2].strip('/')

	def handle(self):
		""" 
		Handles a connection.
		Connection: keep-alive is the default behavior.
		"""

		self.close_connection = False
		while not self.close_connection:
			self.handle_one_request()

	def handle_one_request(self):
		""" 
		Handle a single ICAP request.
		"""

		# Initialize handler state
		self.enc_req = None
		self.enc_req_headers = {}
		self.enc_res_status = None
		self.enc_res_headers = {}
		self.has_body = False
		self.servicename = None
		self.encapsulated = {}
		self.ieof = False
		self.eob = False
		self.methos = None
		self.preview = None
		self.allow = set()

		self.icap_headers = {}
		self.enc_headers = {}
		self.enc_status = None
		self.enc_request = None

		self.icap_response_code = None

		try:
			self.raw_requestline = self.rfile.readline(65537)

			if not self.raw_requestline:
				self.close_connection = True
				return

			self.parse_request()

			mname = self.servicename + '_' + self.command
			if not hasattr(self, mname):
				raise ICAPError(404)

			method = getattr(self, mname)
			if not callable(method):
				raise ICAPError(404)

			method()
			self.wfile.flush()
			msg = '[%s] "%s" %d' % (self.client_address[0], self.requestline, self.icap_response_code)
			LOG.info(msg)
		except socket.timeout as e:
			msg = 'Request timed out: %r', e
			LOG.error(msg)
			self.close_connection = True
		except ICAPError as e:
			self.send_error(e.code, e.message)
		except:
			self.send_error(500)

	def send_error(self, code, message=None):
		""" 
		Send and log an error reply.
		Arguments are the error code, and a detailed message.
		The detailed message defaults to the short entry matching the
		response code.
		This sends an error response (so it must be called before any
		output has been generated), logs the error, and finally sends
		a piece of HTML explaining the error to the user.
		"""

		try:
			short, long = self._responses[code]
		except KeyError:
			short, long = '???', '???'
		if message is None:
			message = short

		if not isinstance(message, str):
			raise ICAPError(500, 'Message must be a string.')

		msg = '[Sending Error] Code: %d, Message: %s' % (code, message)
		LOG.error(msg)

		# No encapsulation
		self.enc_req = None
		self.enc_res_stats = None

		self.set_icap_response(code, message)
		self.set_icap_header('Connection', 'close')
		self.send_headers()

	def send_enc_error(self, code, message=None, body='', contenttype='text/html'):
		""" 
		Send an encapsulated error reply.
		Arguments are the error code, and a detailed message.
		The detailed message defaults to the short entry matching the
		response code.
		This sends an encapsulated error response (so it must be called
		before any output has been generated), logs the error, and
		finally sends a piece of HTML explaining the error to the user.
		"""

		try:
			short, long = self._responses[code]
		except KeyError:
			short, long = '???', '???'
		if message is None:
			message = short

		if not isinstance(message, str):
			raise ICAPError(500, 'Message must be a string.')

		# No encapsulation
		self.enc_req = None

		self.set_icap_response(200)
		self.set_enc_status('HTTP/1.1 %s %s' % (str(code), message))
		self.set_enc_header('Content-Type', contenttype)
		self.set_enc_header('Content-Length', str(len(body)))
		self.send_headers(has_body=True)
		if len(body) > 0:
			self.send_chunk(body)
		self.send_chunk('')

	def version_string(self):
		""" 
		Return the server software version string.
		"""

		return self._server_version + ' ' + self._sys_version

	def date_time_string(self, timestamp=None):
		""" 
		Return the current date and time formatted for a message header.
		"""

		if timestamp is None:
			timestamp = time.time()
		year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
		dts = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (self._weekdayname[wd], 
													day, self._monthname[month], year, 
													hh, mm, ss)
		return dts

	def address_string(self):
		""" 
		Return the client address formatted for logging.
		This version looks up the full hostname using gethostbyaddr(),
		and tries to find a name that contains at least one dot.
		"""

		host, port = self.client_address[:2]
		return socket.getfqdn(host)

	def no_adaptation_required(self):
		""" 
		Tells the client to leave the message unaltered
		If the client allows 204, or this is a preview request than
		a 204 preview response is sent. Otherwise a copy of the message
		is returned to the client.
		"""

		if '204' in self.allow or self.preview != None:
			# We MUST read everything the client sent us
			if self.has_body:
				while True:
					if self.read_chunk() == '':
						break
			self.set_icap_response(204)
			self.send_headers()
		else:
			# We have to copy everything,
			# but it's sure there's no preview
			self.set_icap_response(200)

			self.set_enc_status(' '.join(self.enc_res_status))
			for h in self.enc_res_headers:
				for v in self.enc_res_headers[h]:
					self.set_enc_header(h, v)

			if not self.has_body:
				self.send_headers(False)
				msg = '[%s] "%s" %d' % (self.client_address[0], self.requestline, 200)
				LOG.info(msg)
				return

			self.send_headers(True)
			while True:
				chunk = self.read_chunk()
				self.send_chunk(chunk)
				if chunk == '':
					break

def main(HandlerClass = BaseICAPRequestHandler, ServerClass = ICAPServer):
	"""
	This runs an ICAP server on port 13440 (or the first command line argument).
	"""

	def example_OPTIONS(self):
		self.set_icap_response(200)
		self.set_icap_header('Methods', 'RESPMOD, REQMOD')
		self.set_icap_header('Service', 'ICAP Server' + ' ' + self._server_version)
		self.set_icap_header('Options-TTL', '3600')
		self.send_headers(False)

	def example_REQMOD(self):
		self.no_adaptation_required()

	def example_RESPMOD(self):
		self.no_adaptation_required()

	HandlerClass.example_OPTIONS = example_OPTIONS
	HandlerClass.example_REQMOD = example_REQMOD
	HandlerClass.example_RESPMOD = example_RESPMOD

	if sys.argv[1:]:
		port = 	int(sys.argv[1])
	else:
		port = 13440
	server_address = ('', port)

	icap_server = ServerClass(server_address, HandlerClass)
	
	sa = icap_server.socket.getsockname()
	print "Serving ICAP on", sa[0], "port", sa[1]
	icap_server.serve_forever()


if __name__ == '__main__':
	main()

# ===================================================================================================================== #
