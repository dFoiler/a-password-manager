''' client code '''

host = 'localhost'
port = 373

import binascii			# hexlify
import json			# loads, dumps
import os			# urandom
import socket			# socket
import string			# printable

# local imports
import sys
sys.path.append('..')
from crypto.zkp import *	# authentication
from JASocket.jasocket import *	# JASocket

class Client:
	def __init__(self, host, port):
		# Set up connection
		self.server = JASocket(host, port)
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
		self.server.send(username)
		response = self.server.recv()
		if response == 'Found user.':
			print('[ Found user ]')
		elif response == 'New user. Send token.':
			print('[ New user ]\n[ Sending token ]')
			self.server.send(hex(self.token)[2:])
			self.server_token = self.server.recv()
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
		self_check = self.server.recv().strip()
		self_check = (self_check == 'Authenticated.')
		if self_check:
			print('[ Verfifed client ]')
		if check:
			self.server.send('Authenticated.')
			print('[ Verified server ]')
		else:
			self.server.sendall(b'Failed.')
		return check and self_check
	
	def run_pwds(self):
		assert self.server.recv() == 'Ready.'
		choice = ''
		while choice != 'r' and choice != 's':
			choice = input('[R]etrieve or [S]tore?\n').lower()
			if len(choice) > 0:
				choice = choice[0]
		if choice == 'r':
			print('[ Retrieving ]')
		elif choice == 's':
			print('[ Storing ]')
		else:
			raise Exception('What did you do?')
		self.server.send(choice)
		assert self.server.recv() == 'Which?'
		which = ''
		while len(which) == 0:
			which = input('Which password?\n').strip()
		self.server.send(which)
		if choice == 'r':
			pwd = self.server.recv()
			print('Password:', pwd)
		elif choice == 's':
			assert self.server.recv() == 'To?'
			replacement = input('What are you storing?\n')
			self.server.send(replacement)
			print('[ Sent password ]')
		else:
			raise Exception('What did you do?')
		self.server.send('Done.')
	
	def run(self):
		username = self.send_username()
		print('[ Authenticating ]')
		authenticated = self.authenticate()
		if not authenticated:
			raise Exception('Failed authentication')
		print('[ Running ]')
		# Run cat to show that we're done
		while True:
			self.run_pwds()

if __name__ == "__main__":
	client = Client(host, port)
	client.run()
