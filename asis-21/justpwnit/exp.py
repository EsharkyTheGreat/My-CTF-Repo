#!/usr/bin/python3
import pwn
elf = pwn.context.binary = pwn.ELF("./justpwnit")

pwn.context.terminal = ['tmux', "splitw", "-h"]
if pwn.args.GDB:
    io = pwn.gdb.debug("./justpwnit", gdbscript="c\nb *justpwnit+28")
else:
    io = elf.process()


def set(idx, val):
    io.sendlineafter(b": ", f"{idx}".encode())
    io.sendlineafter(b': ', val)


set(1, b"A"*8)
io.interactive()
