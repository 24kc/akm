#!/usr/bin/env python3

__all__ = ('OPT', 'help', 'main')

import selectors, socket, sys
from enum import IntEnum,unique
from akm.aktalk.mmsock import *
from akm.debug.cdb import *

# debug on/off
set_debug(0)

# select
selector = selectors.DefaultSelector()
# MMSock for mmsocks
mmsocks = []
# others name
NAME = '[others]'

def accept(sock, mask):
	name = NAME
	conn, addr = sock.accept()  # Should be ready
	print('accepted', addr)
	conn.setblocking(False)
	selector.register(conn, selectors.EVENT_READ, read)
	mmsocks.append(MMSock(conn))
	if len(mmsocks) > 1:
			mmsocks[0].sendsem(MMT.SM_SYMGEN)
			mmsocks[1].sendsem(MMT.SM_PUBGEN)

def read(conn, mask):
	'''[noexcept]'''
	mmconn = MMSock(conn)
	addr = mmconn.raddr()
	name = NAME

	data,mmt = mmconn.recv()

	try:
		if data or mmt:
			assert mmsocks
			if len(mmsocks) == 1:
				mmconn.sendsem(MMT.SM_NONE)
			else:
				# forward
				print('forward:', mmt)
				dprint('len(mmsocks) =', len(mmsocks))
				other = mmsocks[1] if mmsocks[0] == mmconn else mmsocks[0]
				if data:
					other.send(data, mmt)
				else:
					other.sendsem(mmt)
		else:
			print('closing', addr)
			i = mmsocks.index(mmconn)
			dprint('mmsocks.index(mmconn) =', i)
			mmsocks.pop(i)
			if mmsocks:
				mmsocks[0].send(f'connect to {name} closed'.encode(), MMT.SERVER_MSG)
			selector.unregister(conn)
			conn.close()

	except Exception as e:
		print('server::read', e)


@unique
class OPT(IntEnum):
	'''options'''
	IP = 0x2411
	PORT = 0x2412
	HELP = 0x2499
	NULL = 0

options = {
	'-ip': OPT.IP,
	'-p': OPT.PORT,
	'-port': OPT.PORT,
	'-h': OPT.HELP,
	'-help': OPT.HELP
}


def main(argv):
	argc = len(argv); optind = 0

	ip = '0.0.0.0'
	port = 10024

	while optind+1 < argc:
		optind += 1
		optstr = argv[optind]
		opt = options.get(optstr)

		if not opt:
			print('unrecognized command line option \''+optstr+'\'')
			sys.exit(1)

		if opt == OPT.IP:
			optind += 1
			if optind < argc:
				argstr = argv[optind]
				ip = argstr
			else:
				opt = OPT.NULL
		elif opt == OPT.PORT:
			optind += 1
			if optind < argc:
				argstr = argv[optind]
				try:
					port = int(argstr)
				except ValueError:
					print('Port must be in (0, 65535) not', argstr)
					sys.exit(1)
			else:
				opt = OPT.NULL
		elif opt == OPT.HELP:
			help(argv)
			sys.exit()
		else:
			assert False,'getopt error'

		if opt == OPT.NULL:
			print('missing argument after \''+optstr+'\'')
			sys.exit(1)

	sock = socket.socket()
	socket_reuse(sock)
	sock.bind((ip, port))
	sock.listen(2)
	sock.setblocking(False)
	selector.register(sock, selectors.EVENT_READ, accept)

	while True:
		events = selector.select()
		for key, mask in events:
			callback = key.data
			callback(key.fileobj, mask)


def help(argv):
	print('Usage:    python3', argv[0], '[options]...')
	print('Valid options are:')
	print(' -ip IP            Set IP address')
	print(' -p/-port PORT     Set the port to be used')
	print(' -h/-help          Display this message')

if __name__ == '__main__':
	main(sys.argv)

