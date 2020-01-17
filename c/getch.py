#!/usr/bin/env python3

from ctypes import cdll

_getch = cdll.LoadLibrary('akm/c/_getch.so')

def peek():
	return _getch.peek()

def getch():
	return _getch.getch()

def getche():
	return _getch.getche()

def reset():
	_getch.end_getch()

def ungetc(c):
	return _getch.unget(c)

def putchar(c):
	_getch.putch(c)

