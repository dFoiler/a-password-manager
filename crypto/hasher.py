from binascii import hexlify, unhexlify
from Crypto.Hash import SHA256

class Hasher:
	''' Wrapper class for PyCryptodome's SHA-256 '''
	def __init__(self, salt):
		'''
		Parameters
		----------
		salt : str
			Salt for the hashing
		'''
		self.salt = unhexlify(salt)
	
	# Actually hash
	def hash(self, text):
		'''
		Function actually doing the hashing
		
		Hashes salt + text
		
		Parameters
		----------
		text : str
			Text to hash with the salt
		
		Returns
		-------
		str, hexlified hash
		'''
		to_hash = self.salt + text.encode()
		hashed = SHA256.new(data=to_hash).digest()
		return hexlify(hashed).decode()
