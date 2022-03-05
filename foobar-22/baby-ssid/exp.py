#!/usr/bin/python3
import pwn
pwn.context.terminal = ['tmux','splitw','-h']

elf = pwn.context.binary =pwn.ELF("./ssId")

if pwn.args.GDB:
    io = pwn.gdb.debug(elf.path,gdbscript='start\n')
elif pwn.args.REMOTE:
    io = pwn.remote("chall.nitdgplug.org",30092)
else:
    io = elf.process()

# payload = b'%1$*269168516$x %1073741824$'
# io.sendline(payload)


io.interactive()