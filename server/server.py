''' server code '''

host = 'localhost'
port = 373


import binascii 		# hexlify
import json			# load, dumps
import os			# urandom
import socket			# socket
import string			# printable

# local imports
import sys
sys.path.append('..')
from crypto.zkp import *	# authentication
from JASocket.jasocket import *	# JASocket

class Server:
	def __init__(self, host, port, queuelength=5):
		# Set up connection
		self.server = JASocket(host, port, is_server=True, queuelength=queuelength)
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
			f.close()
			self.secret = int(self.secret, 16)
		self.token = pow(g, self.secret, p)
		# Get user passwords
		try:
			f = open('client_pwds.txt','r')
			self.user_pwds = json.load(f)
			f.close()
		except FileNotFoundError:
			f = open('client_pwds.txt','w')
			self.user_pwds = {}
			f.write(json.dumps(self.user_pwds))
			f.close()
	
	def get_username(self, client):
		# Receive username
		username = client.recv()
		# Is this a new user?
		if username in self.user_tokens:
			print('[ Found user ]')
			client.send('Found user.')
		else:
			print('[ New user ]')
			# Get user token
			client.send('New user. Send token.')
			token = client.recv()
			print('[ Token:', token, ']')
			self.user_tokens[username] = token
			with open('client_tokens.txt','w') as f:
				f.write(json.dumps(self.user_tokens))
				f.close()
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
			raise Exception('client failed authentication')
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
			with open('client_pwds.txt','w') as f:
				f.write(json.dumps(self.user_pwds))
				f.close()
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
