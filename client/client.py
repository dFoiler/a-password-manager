import binascii			# hexlify
import getpass			# getpass
import json			# loads, dumps
import os			# urandom
import socket			# socket
import sqlite3 as sql		# sqlite3
import string			# printable

# local imports
PATH = os.path.abspath(__file__)
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
	''' This class is for creating client objects '''
	def __init__(self, host, port, wdinp=input, pwinp=getpass.getpass):
		'''
		Parameters
		----------
		host : str
			String naming the host
		port : int
			Integer value of the port of host
		wdinp : function, optional
			Function to take input
		pdinp : function, optional
			Function to take passwords
		'''
		# Set up connection
		self.host = host
		self.server = JASocket(host, port)
		# Set up database
		self.db_conn = sql.connect(PATH+'database.db')
		self.db_conn.row_factory = sql.Row
		self.db_cursor = self.db_conn.cursor()
		self.db_cursor.execute('''CREATE TABLE IF NOT EXISTS servers (host,token)''')
		self.db_cursor.execute('''CREATE TABLE IF NOT EXISTS users
			(username,secret,nmsalt,pwsalt)''')
		# Get server's token
		self.db_cursor.execute('''SELECT * FROM servers WHERE host=?''', (host,))
		rows = self.db_cursor.fetchall()
		if len(rows) == 0:
			self.server_token = -1
		else:
			self.server_token = int(rows[0]['token'], 16)
		# Set input functions
		self.wdinp = wdinp	# word input
		self.pwinp = pwinp	# password input
	
	def get_input(self, prompt='> ', password=False,
		maxlength=None, minlength=None, options=None):
		'''
		Function to get input from the user
		
		Parameters
		----------
		prompt : str, optional
			String to prompt the user with
		password : bool, optional
			Determines if we are inputting a password
		maxlength : int, optional
			Maximum length of input
		minlength : int, optional
			Minimum length of input
		options : list, optional
			List of possible characters to use
		
		Returns
		-------
		str, the user input
		'''
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
		'''
		Function that sends the username to the server
		
		Accounts for possibly already used usernames, being new, etc.
		
		Returns
		-------
		str, the username
		'''
		# Prompt for username
		charlist = [chr(c) for c in range(128) if chr(c).isalnum()]
		print('Enter username:')
		username = self.get_input(minlength=1, maxlength=4000, options=charlist)
		username = username.strip()
		# Get own secret now that we know our username
		self.db_cursor.execute('''SELECT * FROM users
			WHERE username=?''', (username,))
		rows = self.db_cursor.fetchall()
		# Tell the user that we're new
		new_user = (len(rows) == 0)
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
			# Set up user with secret, token, and salts
			self.secret = int(rows[0]['secret'], 16)
			self.token = pow(g, self.secret, p)
			self.nm_salt = rows[0]['nmsalt']
			self.pw_salt = rows[0]['pwsalt']
		# Server recognizes that we're new
		elif response == 'New user. Send token.' and new_user:
			# Set up user with secret, token, and salts
			secret = binascii.hexlify(os.urandom(256)).decode()
			self.nm_salt = binascii.hexlify(os.urandom(16)).decode()
			self.pw_salt = binascii.hexlify(os.urandom(16)).decode()
			self.db_cursor.execute('''INSERT INTO users VALUES(?,?,?,?)''',
				(username,secret,self.pw_salt,self.nm_salt))
			self.secret = int(secret, 16)
			self.token = pow(g, self.secret, p)
			print('[ New user ]\n[ Sending token ]')
			self.server.send(hex(self.token)[2:])
			# Receive the server token
			server_token = self.server.recv()
			# Update database if needed
			if self.server_token == -1:
				self.db_cursor.execute('''INSERT INTO servers VALUES(?,?)''',
					(self.host, server_token))
				self.server_token = int(server_token, 16)
			# If we have it, it should match
			else:
				assert self.server_token == int(server_token, 16)
			self.db_conn.commit()
		# We're new, but server has us on file; recurse
		elif response == 'Username taken.' and new_user:
			print('[ Username taken ]')
			return self.send_username()
		else:
			raise Exception('Something went wrong.')
		return username
	
	def authenticate(self):
		'''
		Runs the authentication protocol with the server
		
		See the crypto package
		
		Returns
		-------
		bool, if the authentication was successful
		'''
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
		'''
		Initiates the password system and sets up salts
		
		Sets up the cipher to encrypt passwords and hasher for names
		'''
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
		# We already have our salts from when we set up the user
		# Initialize ciphers for names and passwords
		self.cipher = AES(password, self.nm_salt)
		# We have a different salt, just in case
		self.hasher = Hasher(self.pw_salt)
	
	def run_pwds(self):
		'''
		Runs the password exchange protocol
		
		Asks the server for the password and runs decryption, unpacking manually
		'''
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
		'''
		Runs the entire program, in sequence
		'''
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
	HOST = 'localhost'
	PORT = 373
	client = Client(HOST, PORT)
	client.run()
