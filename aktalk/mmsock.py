#!/usr/bin/env python3

__all__ = ('MMT', 'socket_reuse', 'MMSock')

from enum import IntEnum,unique
from akm.debug.cdb import *

set_debug(0)

@unique
class MMT(IntEnum):
	'''Message Type'''
	NULL = 0 # Not message

	URGENT_MSG = -24 # Urgent message
	SERVER_MSG = -1 # Server message (str)

	PUBLIC_KEY = 1 # Public key
	SYMM_KEY = 2 # Symmetric key
	PLAIN_TEXT = 3 # Plain text
	CIPHER_TEXT = 4 # Cipher text
	COMMAND = 5 # command

	# semaphore message:
	SM_NONE = 0x2410 # no one is online
	SM_PUBGEN = 0x2420 # generate public key
	SM_SYMGEN = 0x2430 # generate symmetric key
	SM_ENCRYPT = 0x2440 # start encrypt messages

MAX_RECV = 1024 # Maximum receive size per time

class MMSock:
	'''
	Send/Recv
	strong exception-safety guarantee
	'''
	sock = None

	def __init__(self, sock):
		'''[noexcept]'''
		self.sock = sock

	def __eq__(self, other):
		dprint('Compare', self.sock, ' AND ', other.sock)
		return self.sock is other.sock

	def sendsem(self, mmt):
		'''send semaphore [noexcept]'''
		try:
			t = int(mmt)
			head = int.to_bytes(t, 4, 'little', signed=True) + b'\0\0\0\0'
			self.sock.send(head)
			dprint('MMSock::sendsem< head OK:', head)
		except Exception as e:
			print('MMSock::sendsem', e)

	def send(self, b, mmt=MMT.PLAIN_TEXT):
		'''send b [noexcept]'''
		if not b:
			return
		try:
			t = int(mmt)
			b_len = len(b)
			head = int.to_bytes(t, 4, 'little', signed=True) + int.to_bytes(b_len, 4, 'little')
			dprint('MMSock::send< head:', head)
			#self.sock.send(head) # send head with data
			self.sock.sendall(head + b)
			dprint('MMSock::send< head OK')
			dprint('MMSock::send< data OK')
		except Exception as e:
			print('MMSock::send', e)

	def recv(self):
		'''return bytes,MMT [noexcept]'''
		ba = bytearray()
		mmt = None
		try:
			NULL = (b'', MMT.NULL)
			dprint('MMSock::recv> wait for recv head')
			head = self.sock.recv(8)
			dprint('MMSock::recv> head OK')
			if not head:
				return NULL
			dprint('MMSock::recv> head:', head)
			b1 = head[:4]
			b2 = head[4:]
			mmt = int.from_bytes(b1, 'little', signed=True)
			mmt = MMT(mmt)
			data_len = int.from_bytes(b2, 'little')

			remain = data_len
			while remain:
				assert remain > 0
				block_size = MAX_RECV if remain > MAX_RECV else remain
				dprint('MMSock::recv> data: wait for recv', block_size, 'bytes')
				b = self.sock.recv(block_size)
				if not b:
					dprint('MMSock::recv> data: recv ERROR')
					return NULL
				b_len = len(b)
				ba.extend(b)
				dprint('MMSock::recv> data: recv OK', b_len, 'bytes')
				remain -= b_len
				dprint('MMSock::recv> data: remain', remain, 'bytes')

		except Exception as e:
			print('MMSock::recv', e)

		return bytes(ba), mmt

	def raddr(self):
		'''return peer name [noexcept]'''
		name = ''
		try:
			name = self.sock.getpeername()
		except Exception as e:
			print('MMSock::raddr', e)
		return name


def socket_reuse(sock):
	import socket
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
