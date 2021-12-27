import subprocess


def get_rax(idx):
    result = subprocess.check_output(
        f'ROPgadget --binary ./chall{idx} | grep "rax"', shell=True, text=True)
    # print(result)
    all_gadgets = result.splitlines()
    # print(all_gadgets)
    for gadget in all_gadgets:
        addr, instruction = gadget.split(" : ")
        if instruction == "xor rax, rax ; ret":
            # print(addr)
            return int(addr, 16)


def get_mov(idx):
    result = subprocess.check_output(
        f'ROPgadget --binary ./chall{idx} | grep "mov"', shell=True, text=True)
    # print(result)
    all_gadgets = result.splitlines()
    # print(all_gadgets)
    for gadget in all_gadgets:
        addr, instruction = gadget.split(" : ")
        if instruction == "mov qword ptr [rdx], rax ; ret":
            # print(addr)
            return int(addr, 16)
