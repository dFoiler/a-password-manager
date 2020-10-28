from binascii import hexlify, unhexlify
import Crypto.Cipher.AES as CryptoAES	# AES encryption
from Crypto.Hash import SHA256		# SHA256
import os				# urandom

# We use GCM so that we get a tag
class AES:
	def __init__(self, password, salt):
		self.key = AES.pbkdf(password, salt)
		self.mode = CryptoAES.MODE_GCM
	
	def pbkdf(password, salt, iterations=100):
		key = unhexlify(salt) + password.encode()
		for _ in range(iterations):
			key = SHA256.new(data=key).digest()
		return key
	
	def encrypt(self, ptext):
		ptext = ptext.encode()
		cipher = CryptoAES.new(self.key, self.mode)
		ctext, tag = cipher.encrypt_and_digest(ptext)
		encrypted = hexlify(cipher.nonce) + hexlify(ctext) + hexlify(tag)
		return encrypted.decode()
	
	def decrypt(self, encrypted):
		encrypted = encrypted.encode()
		nonce, ctext, tag = encrypted[:32], encrypted[32:-32], encrypted[-32:]
		nonce = unhexlify(nonce)
		ctext = unhexlify(ctext)
		tag = unhexlify(tag)
		cipher = CryptoAES.new(self.key, self.mode, nonce)
		ptext = cipher.decrypt_and_verify(ctext, tag)
		return ptext.decode()
