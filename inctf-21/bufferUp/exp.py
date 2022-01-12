import pwn
pwn.context.terminal = ['tmux', 'splitw', '-h']

elf = pwn.context.binary = pwn.ELF("./chall")

if pwn.args.GDB:
    p = pwn.gdb.debug(elf.path, '''c\n''')
elif pwn.args.REMOTE:
    p = pwn.remote("gc1.eng.run", 30910)
else:
    p = pwn.process(elf.path)

p.interactive()