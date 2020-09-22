''' client code '''

host = 'localhost'
port = 373

import socket
import string
import binascii

def unwrap(data):
	return ''.join(chr(c) for c in data).strip()

class Client:
	def __init__(self, host, port):
		self.server = socket.socket()
		self.server.connect((host, port))
	
	def authenticate(self):
		# Prompt for username
		username = ''
		while True:
			username = input('Enter username: ')
			if any(not c.isalnum() for c in username):
				print('Only alphanumeric characters please.')
			elif len(username) == 0 or len(username) > 4096:
				print('Fewer than 4096 characters please.')
			else:
				break
		username = username.strip()
		print('[ Sending username "' + username + '" to server ]')
		self.server.sendall(username.encode())
		response = self.server.recv(4096)
		if response == b'Found user.\n':
			print('[ Found user ]')
		elif response == b'New user. Send token.\n':
			print('[ New user ]\n[ Generating token ]')
			import os
			self.server.sendall(binascii.hexlify(os.urandom(256)))
		else:
			raise Exception('Something went wrong.')
		return username
	
	def run(self):
		username = self.authenticate()
		# Run cat to show that we're done
		while True:
			self.server.sendall(input('Input: ').encode())
			print('Server:', unwrap(self.server.recv(4096)))

client = Client(host, port)
client.run()
