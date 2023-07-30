#!/usr/bin/env python3

from pwn import *

elf = ELF("./random.elf")
rand_elf = ELF("../C/my_rand.elf")

s  = remote("challs.tfcctf.com", 32550)
# s = process(elf.path)
r = process([rand_elf.path, "10"])

def main():

	for i in range(10):
		rand = r.recvline(False)
		s.sendline(rand)
		
	s.interactive()

if __name__=="__main__":
	main()