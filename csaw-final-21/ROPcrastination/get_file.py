import pwn
import os


def create_files(idx, password):
    try:
        with pwn.remote("auto-pwn.chal.csaw.io", 11000+idx) as io:
            io.recvuntil(b">")
            io.sendline(password)
            io.recvuntil(
                b"-------------------------------------------------------------------\n")
            elf = io.recvuntil(
                b"-------------------------------------------------------------------\n", drop=True)
            f = open(f"binary_{idx}.txt", "wb+")
            f.write(elf)
            f.close()
        os.system(f"cat binary_{idx}.txt | xxd -r > chall{idx}")
    except Exception:
        print(Exception)


def create_heap_file(idx, password):
    try:
        with pwn.remote("auto-pwn.chal.csaw.io", 11000+idx) as io:
            io.recvuntil(b">")
            io.sendline(password)
            io.recvuntil(
                b"-------------------------------------------------------------------\n")
            elf = io.recvuntil(
                b"-------------------------------------------------------------------\n", drop=True)
            f = open(f"binary_{idx}.txt", "wb+")
            f.write(elf)
            f.close()
        os.system(f"cat binary_{idx}.txt | xxd -r > chall{idx}")
        os.system(
            f'patchelf --set-rpath /mnt/c/Users/Acer/Desktop/Hacking/HeapLAB/.glibc/glibc_2.24 ./chall{idx}')
        os.system(
            f'patchelf --set-interpreter /mnt/c/Users/Acer/Desktop/Hacking/HeapLAB/.glibc/glibc_2.24/ld.so.2 ./chall{idx}')
    except Exception:
        print(Exception)
