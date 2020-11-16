from binascii import hexlify, unhexlify
from Crypto.Hash import SHA256

class Hasher:
	def __init__(self, salt):
		self.salt = unhexlify(salt)
	
	# Actually hash
	def hash(self, text):
		to_hash = self.salt + text.encode()
		hashed = SHA256.new(data=to_hash).digest()
		return hexlify(hashed).decode()
