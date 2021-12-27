import pwn
f = open("./file", "rb")
io = pwn.process(["./maze_public"], shell=True, stderr=f)
io.interactive()
