''' server code '''

host = 'localhost'
port = 373


import binascii 		# hexlify
import json			# load, dumps
import os			# urandom
import socket			# socket
import string			# printable

# local imports
if __name__ == "__main__":	# Running the program locally
	import sys
	sys.path.append('..')
from helpers import *
from crypto.zkp import *	# authentication
from JASocket.jasocket import *	# JASocket

class Server:
	def __init__(self, host, port, queuelength=5):
		# Set up connection
		self.server = JASocket(host, port, is_server=True, queuelength=queuelength)
		# Gather user tokens
		self.user_tokens = loadfile('client_tokens.txt', default={})
		# Gather own secret
		secret = binascii.hexlify(os.urandom(256)).decode()
		self.secret = loadfile('secret.txt', default={'secret':secret})
		self.secret = int(self.secret['secret'], 16)
		self.token = pow(g, self.secret, p)
		# Get user passwords
		self.user_pwds = loadfile('client_pwds.txt', default={})
	
	def get_username(self, client):
		# Receive username
		data = client.recv()
		new_user, username = data[:3], data[4:]
		if new_user == 'New':
			new_user = True
		elif new_user == 'Old':
			new_user = False
		else:
			raise Exception('Corrupted username: ' + str(data))
		# Is this a new user?
		if username in self.user_tokens:
			# If user was new, recurse
			if new_user:
				client.send('Username taken.')
				return self.get_username(client)
			# Else proceed normally
			print('[ Found user ]')
			client.send('Found user.')
		else:
			print('[ New user ]')
			# Get user token
			client.send('New user. Send token.')
			token = client.recv()
			print('[ Token:', token, ']')
			self.user_tokens[username] = token
			writefile('client_tokens.txt', self.user_tokens)
			# Send our token
			client.send(hex(self.token)[2:])
		# Check if the username has passwords
		if username not in self.user_pwds:
			self.user_pwds[username] = {}
			with open('client_pwds.txt','w') as f:
				f.write(json.dumps(self.user_pwds))
				f.close()
		return username
	
	def authenticate(self, client, token):
		# Client proves first
		print('[ Verifying client ]')
		verifier = Verifier(client,token)
		check = verifier.run(256)
		# Server proves second
		print('[ Verifying server ]')
		prover = Prover(client, self.secret)
		prover.run(256)
		# Run checks
		if check:
			client.send('Authenticated.')
		else:
			client.send('Failed.')
		self_check = client.recv().strip()
		self_check = (self_check == 'Authenticated.')
		# Failure
		if not check or not self_check:
			client.close()
			if not check:
				raise Exception('client failed authentication')
			if not self_check:
				raise Exception('server failed authentication')
		return check and self_check
	
	def run_pwds(self, client, username):
		client.send('Ready.')
		choice = client.recv()
		client.send('Which?')
		which = client.recv()
		# Retrieve
		if choice == 'r':
			print('[ Retrieving',which,']')
			if which in self.user_pwds[username]:
				client.send(self.user_pwds[username][which])
				print('[ Found ]')
			else:
				client.send('[ Password not found ]')
				print('[ Not found ]')
		# Store
		elif choice == 's':
			print('[ Storing to',which,']')
			client.send('To?')
			replacement = client.recv()
			self.user_pwds[username][which] = replacement
			writefile('client_pwds.txt', self.user_pwds)
		else:
			client.send('Invalid.')
		assert client.recv() == 'Done.'
	
	def run_client(self, client, addr):
		# Check the username
		username = self.get_username(client)
		print(addr[0], 'is', username)
		# Run the authentication protocol
		user_token = int(self.user_tokens[username], 16)
		print('[ Authenticating', addr[0], ']')
		authenticated = self.authenticate(client, user_token)
		print('[ Running ]')
		# Run password protocol
		while True:
			self.run_pwds(client, username)
	
	def run(self):
		print('[ Running ]')
		while True:
			try:
				# Accept client
				client, addr = self.server.accept()
				print('[ Connected to', addr[0], ']')
				# This server should never crash
				self.run_client(client, addr)
			except KeyboardInterrupt:
				# Ok, if you said to die, we'll die
				print('[ Exiting ]')
				exit()
			except Exception as e:
				print('[ Error with',addr[0],':',e,']')
			print('[ Closing ]')
			client.close()

if __name__ == "__main__":
	server = Server(host, port)
	server.run()
