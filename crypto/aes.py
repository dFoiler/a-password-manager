from binascii import hexlify, unhexlify
import Crypto.Cipher.AES as CryptoAES	# AES encryption
from Crypto.Hash import SHA256		# SHA256
import os				# urandom

# We use GCM so that we get a tag
class AES:
	''' Wrapper class for PyCrytoDome's AES '''
	def __init__(self, password, salt):
		'''
		Parameters
		----------
		password : str
			String of the password to encrypt with
		salt : str
			Hex string of the salt
		'''
		self.key = AES.pbkdf(password, salt)
		self.mode = CryptoAES.MODE_GCM
	
	def pbkdf(password, salt, iterations=100):
		'''
		Password-based key-generation function
		
		Hashes the salt + password an iterations number of times
		
		Parameters
		----------
		password : str
			String of the password to encrypt with
		salt : str
			Hex string of the salt
		
		Returns
		-------
		bytes, the key generated from the password and salt
		'''
		key = unhexlify(salt) + password.encode()
		for _ in range(iterations):
			key = SHA256.new(data=key).digest()
		return key
	
	def encrypt(self, ptext):
		'''
		Encryption method, wrapping PyCryptoDome's AES-GCM
		
		Parameters
		----------
		ptext : str
			String for the plaintext to encrypt
		
		Returns
		-------
		str, hexlified encrypted plaintext
		'''
		ptext = ptext.encode()
		cipher = CryptoAES.new(self.key, self.mode)
		ctext, tag = cipher.encrypt_and_digest(ptext)
		encrypted = hexlify(cipher.nonce) + hexlify(ctext) + hexlify(tag)
		return encrypted.decode()
	
	def decrypt(self, ctext):
		'''
		Decryption method, wrapping PyCryptoDome's AES-GCM
		
		Parameters
		----------
		ctext : str
			Ciphertext to decrypt, as from the encryption
		
		Returns
		-------
		str, the decrypted ciphertext
		'''
		encrypted = ctext.encode()
		nonce, ctext, tag = encrypted[:32], encrypted[32:-32], encrypted[-32:]
		nonce = unhexlify(nonce)
		ctext = unhexlify(ctext)
		tag = unhexlify(tag)
		cipher = CryptoAES.new(self.key, self.mode, nonce)
		ptext = cipher.decrypt_and_verify(ctext, tag)
		return ptext.decode()
