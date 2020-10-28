''' client code '''

host = 'localhost'
port = 373

import binascii			# hexlify
import json			# loads, dumps
import os			# urandom
import socket			# socket
import string			# printable

# local imports
import sys			# TODO: Fix this to work for other directories
sys.path.append('..')
from crypto.aes import *
from crypto.zkp import *	# authentication
from JASocket.jasocket import *	# JASocket

class Client:
	def __init__(self, host, port):
		# Set up connection
		self.server = JASocket(host, port)
		# Get server's token
		self.server_tokens = loadfile('server_tokens.txt')
		if host not in self.server_tokens:
			self.server_tokens[host] = '-1'
			writefile('server_tokens.txt', self.server_tokens)
		self.server_token = int(self.server_tokens[host], 16)
	
	def send_username(self):
		# Prompt for username
		username = ''
		while True:
			username = input('Enter username: ')
			# Pinrtable usernames with reasonable lengths only
			if any(not c.isalnum() for c in username):
				print('Only alphanumeric characters please.')
			elif len(username) == 0 or len(username) > 4096:
				print('Fewer than 4096 characters please.')
			else:
				break
		username = username.strip()
		# Get own secret now that we know our username
		self.secrets = loadfile('secrets.txt')
		# Tell the user that we're new
		new_user = username not in self.secrets
		# We'll want this later
		self.new_user = new_user
		if new_user:
			print('[ New user ]')
		print('[ Sending username "' + username + '" to server ]')
		self.server.send(('New:' if new_user else 'Old:')+username)
		response = self.server.recv()
		# We're already in the system
		if response == 'Found user.' and not new_user:
			print('[ Found user ]')
			self.secret = int(self.secrets[username], 16)
			self.token = pow(g, self.secret, p)
		# Server recognizes that we're new
		elif response == 'New user. Send token.' and new_user:
			# Generate secret and token
			self.secrets[username] = binascii.hexlify(os.urandom(256)).decode()
			writefile('secrets.txt', self.secrets)
			self.secret = int(self.secrets[username], 16)
			self.token = pow(g, self.secret, p)
			print('[ New user ]\n[ Sending token ]')
			self.server.send(hex(self.token)[2:])
			# Receive the server token
			self.server_tokens[host] = self.server.recv()
			writefile('server_tokens.txt',self.server_tokens)
			self.server_token = int(self.server_tokens[host], 16)
		# We're new, but server has us on file; recurse
		elif response == 'Username taken.' and new_user:
			print('[ Username taken ]')
			return self.send_username()
		else:
			raise Exception('Something went wrong.')
		return username
	
	def authenticate(self):
		return True
		# Client proves first
		print('[ Verifying client ]')
		prover = Prover(self.server, secret=self.secret)
		prover.run(256)
		# Server proves second
		print('[ Verifying server ]')
		verifier = Verifier(self.server, self.server_token)
		check = verifier.run(256)
		self_check = self.server.recv().strip()
		# Checking
		self_check = (self_check == 'Authenticated.')
		if self_check:
			print('[ Verfifed client ]')
		if check:
			self.server.send('Authenticated.')
			print('[ Verified server ]')
		else:
			self.server.send('Failed.')
		return check and self_check
	
	def init_pwds(self):
		# Extract password
		password = ''
		while not password:
			password = input('Master password: ')
			if any(c not in string.printable for c in password):
				print('Password may only have printable characters.')
				continue
			if len(password) > 4096:
				print('Password may be up to 4096 characters.')
				continue
		# TODO: I might consider forcing the user to enter the password twice, for correctness
		# Get our salt
		salts = loadfile('salts.txt')
		if self.username not in salts:
			salts[self.username] = binascii.hexlify(os.urandom(16)).decode()
			writefile('salts.txt', salts)
		# Initialize cipher
		self.cipher = AES(password, salts[self.username])
	
	def run_pwds(self):
		# Wait for the server to be ready
		assert self.server.recv() == 'Ready.'
		# User selects a choice
		choice = ''
		while choice != 'r' and choice != 's':
			choice = input('[R]etrieve or [S]tore?\n').lower()
			# Sending nothing requires this edge check
			if len(choice) > 0:
				choice = choice[0]
		# Send and receive
		self.server.send(choice)
		assert self.server.recv() == 'Which?'
		# Same rules as the choice hold here
		which = ''
		while len(which) == 0:
			which = input('Which password?\n').strip()
		self.server.send(which)
		# Retrieving
		if choice == 'r':
			# TODO: Add padding to avoid length-extension attacks
			encrypted = self.server.recv()
			if encrypted == '[ Password not found ]':
				print('[ Password not found ]')
			else:
				decrypted = self.cipher.decrypt(encrypted)
				print('Password:', decrypted)
		# Storing
		elif choice == 's':
			assert self.server.recv() == 'To?'
			# Ask use about randomizing passwords
			is_random = ''
			while is_random != 'r' and is_random != 'e':
				is_random = input('[R]andomize or [E]nter?\n').lower()
				if len(is_random) > 0:
					is_random = is_random[0]
			replacement = ''
			if is_random == 'r':
				# Lazy randint
				charlist = [chr(c) for c in range(33,126)]
				for _ in range(16):
					rand = int(binascii.hexlify(os.urandom(4)), 16)
					replacement += charlist[rand % (126-33)]
			elif is_random == 'e':
				replacement = input('What are you storing?\n')
			encrypted = self.cipher.encrypt(replacement)
			self.server.send(encrypted)
			print('[ Sent password ]')
		# This shouldn't be possible
		else:
			raise Exception('What did you do?')
		self.server.send('Done.')
	
	def run(self):
		# Get the username; we don't use it anywhere, really
		self.username = self.send_username()
		# Authentication protocol
		print('[ Authenticating ]')
		authenticated = self.authenticate()
		if not authenticated:
			raise Exception('Failed authentication')
		# Run the password program to show that we're done here
		print('[ Running ]')
		self.init_pwds()
		while True:
			try:
				self.run_pwds()
			except KeyboardInterrupt:
				print('[ Exiting ]')
				break

if __name__ == "__main__":
	client = Client(host, port)
	client.run()
