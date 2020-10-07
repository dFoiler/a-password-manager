''' Just another socket '''

import json		# loads, dumps
import socket		# socket
import string		# printable

''' Some helper functions '''

# Tests if a string is printable with string.printable
def is_printable(s: str):
	if not isinstance(s, str):
		raise TypeError('is_printable takes str')
	for c in s:
		if c not in string.printable:
			return False
	return True

# Loads a dictionary from a file
def loadfile(name: str, default={}):
	if not isinstance(name, str):
		raise TypeError('loadfile takes str')
	ret = default
	try:
		f = open(name, 'r')
		ret = json.load(f)
		f.close()
	except FileNotFoundError:
		f = open(name, 'w')
		f.write(json.dumps(default))
		f.close()
	return ret

# Writes a dictionary to a file
def writefile(name: str, data: dict):
	if not isinstance(name, str):
		raise TypeError('writefile takes str')
	if not isinstance(data, dict):
		raise TypeError('writefile takes dict')
	f = open(name, 'w')
	f.write(json.dumps(data))
	f.close()

class JASocket:
	def __init__(self, host, port, is_server=False, queuelength=5, sd=None):
		self.is_server = is_server
		# Pass in a socket through client
		if sd:
			self.socket = sd
			return
		# Keep going
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if not is_server:
			self.socket.connect((host, port))
		else:
			self.socket.bind((host, port))
			self.socket.listen(queuelength)
	
	# Accept connections
	def accept(self):
		if not self.is_server:
			raise Exception('client cannot accept')
		client,addr = self.socket.accept()
		return JASocket(None, None, sd=client), addr
	
	# Input a string
	def send(self, message: str):
		if not isinstance(message, str):
			raise TypeError('can only send strings')
		if not is_printable(message):
			raise Exception('message not printable')
		if len(message) >= 4096:
			raise Exception('message too long')
		self.socket.sendall(message.encode())
	
	# Returns a string
	def recv(self):
		message = self.socket.recv(4096).decode()
		if not is_printable(message):
			raise Exception('message corrupted')
		return message
	
	# Closes
	def close(self):
		self.socket.close()
