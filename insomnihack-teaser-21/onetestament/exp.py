#!/usr/bin/python3
import pwn
pwn.context.terminal = ['tmux', 'splitw', '-h']
elf = pwn.context.binary = pwn.ELF("./onestatement")

if pwn.args.GDB:
    io = pwn.gdb.debug(elf.path, gdbscript="""\nc\n""")
elif pwn.args.REMOTE:
    io = pwn.remote()
else:
    io = elf.process()

'''
1 -24
2 - 48
3 - 96
4 - 128
'''


def create(size, data):
    io.sendlineafter("choice: ", b"1")
    io.sendlineafter("choice: ", str(size).encode())
    io.sendafter("content: ", data)


def edit(idx, data):
    io.sendlineafter("choice: ", b"3")
    io.sendlineafter("index: ", str(idx).encode())
    io.sendlineafter("content: ", data)


def delete(idx):
    io.sendlineafter("choice: ", b"4")
    io.sendlineafter("index: ", str(idx).encode())


# create(4, b'A'*8+b'\n')
# create(1, b'B'*8+b'\n')
# delete(0)
# edit(0, b'C'*7+b'\n')
io.interactive()
