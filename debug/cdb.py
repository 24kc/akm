#!/usr/bin/env python3

__all__ = ('NDEBUG', 'set_debug', 'dprint')

NDEBUG = False

def set_debug(flag):
	global NDEBUG
	NDEBUG = not flag

def dprint(*objects, **kwargs):
	if NDEBUG:
		return
	print(*objects, **kwargs)

