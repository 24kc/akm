#!/usr/bin/env python3

import sys, base64
from akm.akes.Akes import AKES
from Crypto.PublicKey import RSA as Cipher

_all_key_bits = (2048, 2560, 3072, 4096, 5120, 7680, 10240, 15360, 20480, 25600)

class RSA(AKES):
	all_key_bits = _all_key_bits

	__block_size_decrypt = None # sizeof key
	__block_size_encrypt = None # __block_size_decrypt - 2 - sizeof Hash
	__cipher = None
	
	def generate_key(self, key_bits=0, **kwargs):
		''' 返回一个密钥对, 请忽略此返回值, 总是使用load_key('f')加载密钥 '''
		if not key_bits:
			key_bits = self.all_key_bits[0]
		if key_bits not in self.all_key_bits:
			raise ValueError('key_bits Error')

		key_file = kwargs.get('key_file')
		password = kwargs.get('password')

		if password:
			raise ValueError('akes RSA does not support generating keys with passwords \
and use key load from file when encrypting/decrypting')

		rsa = Cipher.generate(key_bits)

		if key_file:
			with open(key_file, 'wb') as f:
				f.write(rsa.exportKey('PEM'))
			with open(key_file+'.pub', 'wb') as f:
				f.write(rsa.publickey().exportKey('PEM'))
		return rsa
	
	
	def load_key(self, key_file):
		with open(key_file, 'rb') as f:
			key = Cipher.importKey(f.read())
		key_attr = {}
		key_bits = _sizeof_key(key) * 8
		key_attr['key_bits'] = key_bits
		key_attr['key_type'] = 'Public' if _is_public(key) else 'Private'
		return key, key_attr
	
	
	def fernet(self, key):
		if True:
			from Crypto.Cipher import PKCS1_OAEP as PKCS1
		else:
			from Crypto.Cipher import PKCS1_v1_5 as PKCS1
		from Crypto.Hash import MD5 as HashAlgo
	
		hashalgo = HashAlgo
		self.__cipher = PKCS1.new(key, hashalgo)
	
		key_bytes = _sizeof_key(key)
	
		self.__block_size_encrypt = key_bytes - 2 - hashalgo.digest_size * 2
		self.__block_size_decrypt = key_bytes
	
	
	def encrypt(self, b):
		block_size = self.__block_size_encrypt
		b_len = len(b)
		n = int( b_len / block_size )
		r = b_len % block_size
		ba = bytearray()
		for i in range(0, n*block_size, block_size):
			tb = self.__cipher.encrypt( b[i:i+block_size] )
			ba.extend(tb)
		if r:
			tb = self.__cipher.encrypt( b[-r:] )
			ba.extend(tb)
		return bytes(ba)
	
	
	def decrypt(self, b):
		block_size = self.__block_size_decrypt
		b_len = len(b)
		n = int( b_len / block_size )
		r = b_len % block_size
		ba = bytearray()
		for i in range(0, n*block_size, block_size):
			tb = self.__cipher.decrypt( b[i:i+block_size] )
			ba.extend(tb)
		if r:
			tb = self.__cipher.decrypt( b[-r:] )
			ba.extend(tb)
		return bytes(ba)

	# expand
	#def export_key(self):
	#	return 

	def import_key(self, b):
		return Cipher.importKey(b)
		
	
	
#####################   RSA:    #######################
	
	
def _is_public(key):
	''' return key == public_key ? True : False '''
	return True if not _is_private(key) else False
	
	
def _is_private(key):
	''' return key == private_key ? True : False '''
	return True if key.has_private() else False
	
	
def _sizeof_key(key):
	''' fix for termux '''
	try:
		key_bytes = key.size() // 8 + 1
	except NotImplementedError:
		key_bytes = key.size_in_bytes()
	return key_bytes

