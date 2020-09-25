''' client code '''

host = 'localhost'
port = 373

import json		# loads, dumps
import socket		# socket
import string		# printable
import os		# urandom
import binascii		# hexlify
from zkp import *	# authentication

def unwrap(data):
	return ''.join(chr(c) for c in data).strip()

class Client:
	def __init__(self, host, port):
		# Set up connection
		self.server = socket.socket()
		self.server.connect((host, port))
		# Get server's token
		try:
			f = open('server_tokens.txt','r')
			self.server_tokens = json.load(f)
			f.close()
			if host not in self.server_tokens:
				self.server_tokens[host] = '-1'
		except FileNotFoundError:
			f = open('server_tokens.txt','w')
			self.server_tokens = {}
			f.write(json.dumps(self.server_tokens))
			f.close()
			self.server_tokens[host] = '-1'
		self.server_token = int(self.server_tokens[host], 16)

	def send_username(self):
		# TODO: Do something about repeat usernames
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
		# Get own secret now that we know our username :/
		try:
			f = open('secrets.txt','r')
			self.secret = json.load(f)
			f.close()
			self.secret = int(self.secret[username], 16)
		except FileNotFoundError:
			f = open('secrets.txt','w')
			secret = binascii.hexlify(os.urandom(256)).decode()
			f.write(json.dumps({username:self.secret}))
			self.secret = int(secret, 16)
		except KeyError:
			f = open('secrets.txt','w')
			secret = binascii.hexlify(os.urandom(256)).decode()
			self.secret[username] = secret
			f.write(json.dumps(self.secret))
			self.secret = int(secret, 16)
		self.token = pow(g, self.secret, p)
		print('[ Sending username "' + username + '" to server ]')
		self.server.sendall(username.encode())
		response = self.server.recv(4096)
		if response == b'Found user.\n':
			print('[ Found user ]')
		elif response == b'New user. Send token.\n':
			print('[ New user ]\n[ Sending token ]')
			self.server.sendall(hex(self.token)[2:].encode())
			self.server_token = self.server.recv(4096).decode()
			self.server_tokens[host] = self.server_token
			f = open('server_tokens.txt','w')
			f.write(json.dumps(self.server_tokens))
			f.close()
			self.server_token = int(self.server_token, 16)
		else:
			raise Exception('Something went wrong.')
		return username
	
	def authenticate(self):
		# Client proves first
		print('[ Verifying client ]')
		prover = Prover(self.server, secret=self.secret)
		prover.run(256)
		# Server proves second
		print('[ Verifying server ]')
		verifier = Verifier(self.server, self.server_token)
		check = verifier.run(256)
		self_check = self.server.recv(4096).strip()
		self_check = (self_check == b'Authenticated.')
		if self_check:
			print('[ Verfifed client ]')
		if check:
			self.server.sendall(b'Authenticated.')
			print('[ Verified server ]')
		else:
			self.server.sendall(b'Failed.')
		return check and self_check
	
	def run(self):
		username = self.send_username()
		print('[ Authenticating ]')
		authenticated = self.authenticate()
		if not authenticated:
			raise Exception('Failed authentication')
		print('[ Running ]')
		# Run cat to show that we're done
		while True:
			self.server.sendall(input('Input: ').encode())
			print('Server:', unwrap(self.server.recv(4096)))

client = Client(host, port)
client.run()
