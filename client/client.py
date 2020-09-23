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
		# Get own secret
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
		# Very secure
		return True
	
	def run(self):
		username = self.send_username()
		# Run cat to show that we're done
		while True:
			self.server.sendall(input('Input: ').encode())
			print('Server:', unwrap(self.server.recv(4096)))

client = Client(host, port)
client.run()
