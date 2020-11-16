''' client code '''

host = 'localhost'
port = 373

import binascii			# hexlify
import getpass			# getpass
import json			# loads, dumps
import os			# urandom
import socket			# socket
import string			# printable

# local imports
PATH = './' + __file__
PATH = PATH[:-PATH[::-1].find('/')]
# Go back up a directory from here
import sys
sys.path.append(PATH+'..')
from helpers import *		# get_rand_word
from crypto.aes import *	# encrypt, decrypt
from crypto.hasher import *	# hash
from crypto.zkp import *	# authentication
from JASocket.jasocket import *	# JASocket

class Client:
	def __init__(self, host, port, wdinp=input, pwinp=getpass.getpass):
		# Set up connection
		self.server = JASocket(host, port)
		# Get server's token
		self.server_tokens = loadfile(PATH+'server_tokens.txt')
		if host not in self.server_tokens:
			self.server_tokens[host] = '-1'
			writefile(PATH+'server_tokens.txt', self.server_tokens)
		self.server_token = int(self.server_tokens[host], 16)
		# Set input functions
		self.wdinp = wdinp	# word input
		self.pwinp = pwinp	# password input
	
	def get_input(self, prompt='> ', password=False,
		maxlength=None, minlength=None, options=None):
		# This is convenience
		inputfunction = self.pwinp if password else self.wdinp
		while True:
			# Get inputs
			r = inputfunction(prompt)
			# Run checks
			if maxlength and len(r) > maxlength:
				print('Length cannot exceed', maxlength)
			elif minlength and len(r) < minlength:
				print('Length cannot go below', minlength)
			elif options and any(c not in options for c in r):
				print('Must be in', options)
			else:
				return r
	
	def send_username(self):
		# Prompt for username
		charlist = [chr(c) for c in range(128) if chr(c).isalnum()]
		print('Enter username:')
		username = self.get_input(minlength=1, maxlength=4000, options=charlist)
		username = username.strip()
		# Get own secret now that we know our username
		self.secrets = loadfile(PATH+'secrets.txt')
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
			writefile(PATH+'secrets.txt', self.secrets)
			self.secret = int(self.secrets[username], 16)
			self.token = pow(g, self.secret, p)
			print('[ New user ]\n[ Sending token ]')
			self.server.send(hex(self.token)[2:])
			# Receive the server token
			self.server_tokens[host] = self.server.recv()
			writefile(PATH+'server_tokens.txt',self.server_tokens)
			self.server_token = int(self.server_tokens[host], 16)
		# We're new, but server has us on file; recurse
		elif response == 'Username taken.' and new_user:
			print('[ Username taken ]')
			return self.send_username()
		else:
			raise Exception('Something went wrong.')
		return username
	
	def authenticate(self, debug=False):
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
		password = ''; confirm = 'unequal'
		# Password has to confirm because this is master
		while password != confirm:
			print('Master password:')
			password = self.get_input(minlength=1, maxlength=4000,
				options=string.printable, password=True)
			print('Confirm password:')
			confirm = self.get_input(minlength=1, maxlength=4000,
				options=string.printable, password=True)
			if password != confirm:
				print('[ Passwords do not match ]')
		# Get our salts
		salts = loadfile(PATH+'salts.txt')
		if self.username not in salts:
			salts[self.username] = {
				'pw':binascii.hexlify(os.urandom(16)).decode(),
				'nm':binascii.hexlify(os.urandom(16)).decode()
			}
			writefile(PATH+'salts.txt', salts)
		# Initialize ciphers for names and passwords
		self.cipher = AES(password, salts[self.username]['pw'])
		# We have a different salt, just in case
		self.hasher = Hasher(salts[self.username]['nm'])
	
	def run_pwds(self):
		# Wait for the server to be ready
		assert self.server.recv() == 'Ready.'
		# User selects a choice
		print('[R]etrieve or [S]tore')
		choice = self.get_input(minlength=1, maxlength=1, options=['r','s','R','S'])
		choice = choice.lower()
		# Send and receive
		self.server.send(choice)
		assert self.server.recv() == 'Which?'
		# Same rules as the choice hold here
		print('Which password?')
		nm = self.get_input(minlength=1, maxlength=4000)
		# Send hashed name
		self.server.send(self.hasher.hash(nm))
		# Retrieving
		if choice == 'r':
			encrypted = self.server.recv()
			if encrypted == '[ Password not found ]':
				print('[ Password not found ]')
			else:
				decrypted = self.cipher.decrypt(encrypted)
				# Extract the test_which in case of corruption
				test_nm, pw = decrypted[:len(nm)], decrypted[len(nm):]
				assert nm == test_nm
				print('Password: "' + pw + '"')
		# Storing
		elif choice == 's':
			assert self.server.recv() == 'To?'
			# Ask use about randomizing passwords
			print('[R]andom or [E]nter?')
			is_random = self.get_input(minlength=1, maxlength=1, options=['r','e','R','E'])
			replacement = ''
			if is_random in ['r','R']:
				charlist = [chr(c) for c in range(33,128)]
				replacement = get_rand_word(32, charlist)
			elif is_random in ['e', 'E']:
				print('Enter password:')
				replacement = self.get_input(minlength=1, maxlength=1000)
			# We include which as well here, to check for corruption
			self.server.send(self.cipher.encrypt(nm+replacement))
			print('[ Sent password "' + replacement + '" ]')
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
