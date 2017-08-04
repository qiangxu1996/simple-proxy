import sys
import socket
import re

from threading import Thread
from socketserver import ThreadingTCPServer, StreamRequestHandler
from struct import unpack

RE_CONNECT = re.compile(r'CONNECT')
RE_CONTENT_LENGTH = re.compile(r'Content-Length: ')
RE_TRANSFER_ENCODING = re.compile(r'Transfer-Encoding: ')
RE_PROXY_CONNECTION = re.compile(r'Proxy-Connection: ')
RE_HOST = re.compile(r'Host: ')
RE_ADDR = re.compile(r'http://[^/]*/')
RE_BLACK = None

HTTP = 0
HTTPS = 1

def forward(from_sock, to_sock):
	while True:
		try:
			msg = from_sock.recv(2048)
			if not msg:
				from_sock.close()
				to_sock.close()
				break
			to_sock.sendall(msg)
		except:
			from_sock.close()
			to_sock.close()
			break
	
class ReqHandler(StreamRequestHandler):
	def read_message(self, sock_file):
		msg = []
		content_len = 0
		chunked = False
		while True:
			line = sock_file.readline()
			if not line:
				break
			msg.append(line)
			line = line.decode('utf-8')
			if line == '\r\n':
				break
			elif RE_CONTENT_LENGTH.match(line):
				content_len = int(RE_CONTENT_LENGTH.sub('', line))
			elif RE_TRANSFER_ENCODING.match(line):
				if RE_TRANSFER_ENCODING.sub('', line) != 'identity\r\n':
					chunked = True

		if chunked:
			while True:
				chunk_len = sock_file.readline()
				msg.append(chunk_len)
				chunk_len = int(chunk_len, 16)
				if chunk_len == 0:
					line = sock_file.readline()
					msg.append(line)
					break
				line = sock_file.read(chunk_len)
				newline = sock_file.readline()
				msg.append(line)
				msg.append(newline)
		elif content_len != 0:
			line = sock_file.read(content_len)
			msg.append(line)

		return msg
	
	def read_ssl_msg(self, sock_file):
		header = sock_file.read(5)
		body = b''
		content_len = header[-2:]
		content_len = unpack('!H', content_len)[0]
		if content_len != 0:
			body = sock_file.read(content_len)
		msg = b''.join([header, body])
		return msg

	def handle(self):
		self.request.settimeout(60)
		connected_target = ''
		connected_port = 0
		client = None
		req_type = HTTP
		port = 80
		while True:
			if req_type == HTTP:
				try:
					request = self.read_message(self.rfile)
					if not request:
						break
				except:
					self.request.close()
					break

				req_line = request[0].decode('utf-8')
				print(self.request.getpeername(), req_line.strip())
				target = ''
				if not RE_CONNECT.match(req_line):
					# consider as a valid GET or POST request
					request[0] = RE_ADDR.sub('/', req_line).encode('utf-8')
				else:
					req_type = HTTPS

				for i in range(1, len(request)):
					field = request[i].decode('utf-8')
					if field == '\r\n':
						# reached the end of header
						break
					elif RE_PROXY_CONNECTION.match(field):
						# request[i] = RE_PROXY_CONNECTION\
						# 	.sub('Connection: ', field)\
						# 	.encode('utf-8')
						request[i] = b''
					elif RE_HOST.match(field):
						target = RE_HOST.sub('', field).strip()
						if ':' in target:
							target, port = target.split(':')
							port = int(port)

				request = b''.join(request)

				if RE_BLACK and RE_BLACK.search(target):
					print('Target address', target, 'banned.')
					self.request.close()
					break

				if connected_target != target or connected_port != port:
					try:
						if client:
							client.close()
						client = socket.create_connection((target, port), 60)
						connected_target = target
						connected_port = port
					except:
						print('Cannot connect to', target, ':', port, file=sys.stderr)
						self.request.close()
						break
				# client is garenteed to be initialized
				if req_type == HTTP:
					try:
						client.sendall(request)
						response = self.read_message(client.makefile('b'))
						response = b''.join(response)
					except:
						self.request.close()
						client.close()
						break
				else:
					t = Thread(target=forward, args=(client, self.request), daemon=True)
					t.start()
					response = b'HTTP/1.1 200 Connection Established\r\n\r\n'
				try:
					self.wfile.write(response)
					self.wfile.flush()
				except:
					self.request.close()
					break
			else:
				try:
					request = self.request.recv(2048)
					if not request:
						self.request.close()
						client.close()
						break
					client.sendall(request)
				except:
					self.request.close()
					client.close()
					break

if __name__ == '__main__':
	if len(sys.argv) != 2:	
		print("usage: proxy port", file=sys.stderr)
		sys.exit(1)
	
	black_file = open('black-list')
	black_re = black_file.readlines()
	if black_re:
		black_re = [r.strip() for r in black_re]
		black_re = '|'.join(black_re)
		RE_BLACK = re.compile(black_re)
	
	# TODO should also check if integer
	server_port = int(sys.argv[1])

	server = ThreadingTCPServer(('', server_port), ReqHandler)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		server.server_close()
		print('server closed, clean up down.', file=sys.stderr)
		sys.exit(0)
