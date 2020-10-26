from binascii import hexlify, unhexlify
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
	
	def encrypt(self, ptext):
		cipher = CryptoAES.new(self.key, self.mode)
		ctext, tag = cipher.encrypt_and_digest(ptext)
		encrypted = hexlify(cipher.nonce) + hexlify(ctext) + hexlify(tag)
		return encrypted
	
	def decrypt(self, encrypted):
		nonce, ctext, tag = encrypted[:32], encrypted[32:-32], encrypted[-32:]
		nonce = unhexlify(nonce)
		ctext = unhexlify(ctext)
		tag = unhexlify(tag)
		cipher = CryptoAES.new(self.key, self.mode, nonce)
		ptext = cipher.decrypt_and_verify(ctext, tag)
		return ptext
