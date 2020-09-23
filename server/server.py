''' server code '''

host = 'localhost'
port = 373

import socket		# socket
import string		# printable
import os		# urandom
import json		# load, dumps
import binascii 	# hexlify
from zkp import *	# authentication

class Server:
	def __init__(self, host, port, queuelength=5):
		# Set up connection
		self.server = socket.socket()
		self.server.bind((host, port))
		self.server.listen(queuelength)
		# Gather user tokens
		try:
			f = open('client_tokens.txt','r')
			self.user_tokens = json.load(f)
			f.close()
		except FileNotFoundError:
			f = open('client_tokens.txt','w')
			self.user_tokens = {}
			f.write(json.dumps(self.user_tokens))
			f.close()
		# Gather own secret
		try:
			f = open('secret.txt','r')
			self.secret = json.load(f)
			f.close()
			self.secret = int(self.secret['secret'], 16)
		except FileNotFoundError:
			f = open('secret.txt','w')
			self.secret = binascii.hexlify(os.urandom(256)).decode()
			f.write(json.dumps({'secret':self.secret}))
			self.secret = int(self.secret, 16)
		self.token = pow(g, self.secret, p)
	
	def get_username(self, client):
		# Receive username
		username = client.recv(4096)
		username = ''.join(chr(c) for c in username)
		username = username.strip()
		# Test if username is printable
		if any(c not in string.printable for c in username):
			return False
		# Is this a new user?
		if username in self.user_tokens:
			print('[ Found user ]')
			client.sendall(b'Found user.\n')
		else:
			print('[ New user ]')
			# Get user token
			client.sendall(b'New user. Send token.\n')
			token = client.recv(4096).decode()
			print('[ Token:', token, ']')
			self.user_tokens[username] = token
			with open('client_tokens.txt','w') as f:
				f.write(json.dumps(self.user_tokens))
				f.close()
			# Send our token
			client.sendall(hex(self.token)[2:].encode())
		return username
	
	def authenticate(self, client):
		# Very secure
		return True
	
	def run(self):
		print('[ Running ]')
		while True:
			# Accept new user
			client, addr = self.server.accept()
			print('[ Connected to', addr[0], ']')
			# CHeck the username
			username = self.get_username(client)
			if not username:
				print('[', addr[0], 'gave invalid username ]')
				print('[ Closing ]')
				client.sendall(b'Closing.')
				client.close()
				continue
			print(addr[0], 'is', username)
			# Run the authentication protocol
			authenticated = self.authenticate(client)
			if not authenticated:
				print('[', addr[0], 'failed authentification ]')
				print('[ Closing ]')
				client.sendall(b'Closing.')
				client.close()
				continue
			# Run cat to show that we're done
			while True:
				data = client.recv(4096)
				if not data:
					break
				client.sendall(data)
			print('[ Closing ]')
			client.close()

if __name__ == "__main__":
	server = Server(host, port)
	server.run()
