import Crypto.Cipher.AES as CryptoAES	# AES encryption
from Crypto.Hash import SHA256		# SHA256
import os				# urandom

def pbkdf(password, salt, iterations=100):
	key = salt + password
	for _ in range(iterations):
		key = SHA256.new(data=key).digest()
	return key

# We use GCM so that we get a tag
# This is going to be the one part of this sytem that uses bytes
class AES:
	def __init__(self, password, salt):
		self.key = pbkdf(password, salt)
		self.mode = CryptoAES.MODE_GCM
	
	def encrypt(self, ptext: str):
		cipher = CryptoAES.new(self.key, self.mode)
		ctext, tag = cipher.encrypt_and_digest(ptext)
		return cipher.nonce, ctext, tag
	
	def decrypt(self, nonce, ctext, tag):
		cipher = CryptoAES.new(nonce, self.key, self.mode)
		ptext = cipher.decrypt_and_verify(ctext, tag)
		return ptext
