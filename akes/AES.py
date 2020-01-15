#!/usr/bin/env python3

import base64
from akm.akes.Akes import AKES
from Crypto.Cipher import AES as Cipher

_all_key_bits = (128, 192, 256)

class AES(AKES):
	all_key_bits = _all_key_bits

	__key = None
	__cipher = None
	__cipher_status = False

	def generate_key(self, key_bits=0, **kwargs):
		if not key_bits:
			key_bits = self.all_key_bits[0]
		if key_bits not in self.all_key_bits:
			raise ValueError('key_bits Error')
		key_bytes = key_bits // 8
	
		from Crypto.Hash import SHA512 as hashalgo
		ha = hashalgo.new()
	
		key_file = kwargs.get('key_file')
		password = kwargs.get('password')

		if not password:
			from Crypto.Random import random
			rand_list = []
			for _ in range(24):
				i = random.randint(0xffff, 0xffffffff)
				rand_list.append(i)
			password = str(rand_list)
	
		ha.update(f'{password} akm 24k ABC'.encode())
		key = ha.digest()[:key_bytes]
	
		if key_file:
			with open(key_file, 'wb') as f:
				f.write(base64.b64encode(key))
		return key
	
	
	# key_file_name: 密钥文件保存路径
	# load_key('sbc.key') 从文件sbc.key加载密钥, 返回该密钥
	def load_key(self, key_file):
		key = None
		with open(key_file, 'rb') as f:
			s = f.read()
			key = base64.b64decode(s)
		key_bits = len(key) * 8
		if key_bits not in self.all_key_bits:
			raise ValueError('key format error')
		key_attr = {}
		key_attr['key_bits'] = key_bits
		return key, key_attr
	
	
	# 设置要使用的密钥key, 在下一次调用此函数前,加密解密都使用该密钥
	def fernet(self, key):
		if (self.__key != key) or not self.__cipher_status:
			self.__cipher = Cipher.new(key, Cipher.MODE_CBC, b'IV - akm 24k ABC')
			self.__cipher_status = True
			self.__key = key
	
	
	# 加密bytes 返回bytes
	def encrypt(self, b):
		if self.__cipher == None:
			raise ValueError('no key is set')
		n = 16 - len(b) % 16
		b = b + bytes([n]) * n
		self.fernet(self.__key)
		b = self.__cipher.encrypt(b)
		self.__cipher_status = False
		return b
		
	
	# 解密bytes 返回bytes
	def decrypt(self, b):
		if self.__cipher == None:
			raise ValueError('no key is set')
		self.fernet(self.__key)
		b = self.__cipher.decrypt(b)
		self.__cipher_status = False
		n = b[-1]
		if not (0 < n and n <= 16):
			raise ValueError(f'Padding error {n}')
		b = b[:-n]
		return b

