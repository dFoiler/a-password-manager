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
		username = client.recv(4096)
		username = ''.join(chr(c) for c in username)
		username = username.strip()
		# Test if username is printable
		if any(c not in string.printable for c in username):
			raise Exception('client gave invalid username')
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
			client.sendall(b'Authenticated.')
		else:
			client.sendall(b'Failed.')
		self_check = client.recv(4096).strip()
		self_check = (self_check == b'Authenticated.')
		# Failure
		if not check or not self_check:
			client.close()
			raise Exception('client failed authentication')
		return check and self_check
	
	def run_pwds(self, client, username):
		client.sendall(b'Ready.')
		choice = client.recv(4096).decode()
		client.sendall(b'Which?')
		which = client.recv(4096).decode()
		# Retrieve
		if choice == 'r':
			print('[ Retrieving',which,']')
			if which in self.user_pwds[username]:
				client.sendall(self.user_pwds[username][which].encode())
			else:
				client.sendall(b'[ Password not found ]')
		# Store
		elif choice == 's':
			print('[ Storing to',which,']')
			client.sendall(b'To?')
			replacement = client.recv(4096).decode()
			self.user_pwds[username][which] = replacement
			with open('client_pwds.txt','w') as f:
				f.write(json.dumps(self.user_pwds))
				f.close()
		else:
			client.sendall(b'Invalid.')

	def run_client(self, client, addr):
		# Check the username
		username = self.get_username(client)
		print(addr[0], 'is', username)
		# Run the authentication protocol
		user_token = int(self.user_tokens[username], 16)
		print('[ Authenticating', addr[0], ']')
		authenticated = self.authenticate(client, user_token)
		print('[ Running ]')
		# Run cat to show that we're done
		while True:
			self.run_pwds(client, username)
	
	def run(self):
		print('[ Running ]')
		while True:
			# Accept client
			client, addr = self.server.accept()
			print('[ Connected to', addr[0], ']')
			# This server should never crash
			try:
				self.run_client(client, addr)
			except KeyboardInterrupt:
				# Ok, if you said to die, we'll die
				exit()
			except Exception as e:
				print('[ Error with',addr[0],':',e,']')
			print('[ Closing ]')
			client.close()

if __name__ == "__main__":
	server = Server(host, port)
	server.run()
