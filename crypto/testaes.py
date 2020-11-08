from binascii import hexlify
from aes import AES		# AES
import os			# urandom

plaintext = 'this is an arbitrary string'

# Quick check that we can indeed encrypt any standard ASCII
padding = ''.join(chr(c) for c in range(256))

print('[ Initializing ]')
salt = hexlify(os.urandom(16)).decode()
password = hexlify(os.urandom(16))
cipher = AES(salt, password)

print('[ Testing ]')

print('Plaintext:', plaintext)
# Encrypt with padding to prove that the padding works
encrypted = cipher.encrypt(plaintext + padding)
print('Encrypted:', encrypted)

decrypted = cipher.decrypt(encrypted)
decrypted_padding = decrypted[-len(padding):]
# Assert instead of print because it's just padding
assert padding == decrypted_padding
print('Decrypted:', decrypted[:-len(padding)])
