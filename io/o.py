#!/usr/bin/env python3

__all__ = ('sprint',)

def sprint(*objects, **kwargs):
	s = []

	sep = kwargs.get('sep')
	end = kwargs.get('end')
	if not sep:
		sep = ' '
	if not end:
		end = '\n'

	for o in objects:
		s.append(str(o))
		s.append(sep)
	if s:
		s.pop()
	s.append(end)

	return ''.join(s)

