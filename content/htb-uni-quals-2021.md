+++
title = "HTB University Quals 2021"
date = 2021-11-14

[taxonomies]
tags = ["ctf-writeups"]
+++

I played with [ret2rev](https://ret2rev.dev/) and we placed 38th! Great CTF; I appreciated the theme and the challenges were well designed. I've included writeups for the rev challenges I solved. 
<!-- more -->


# vault

```text
After following a series of tips, you have arrived at your destination; a giant vault door. Water drips and steam hisses from the locking mechanism, as you examine the small display - "PLEASE SUPPLY PASSWORD". Below, a typewriter for you to input. You must study the mechanism hard - you might only have one shot...
```
[vault](/ctf/htb-uni-quals-2021/vault)

## reversing

The first place to go is the main funtion! The binary is stripped but binary ninja is kinda enough to detect and rename it automatically, so all that is left is analyzing the function. 

![main function; reads a string from "flag.txt" and checks each char against another char derived from some gross vtable](/ctf/htb-uni-quals-2021/vault_main.png)

It's fairly straightforward for a stripped c++ binary. At the top it opens up an ifstream for flag.txt and then it reads it byte by byte. Each byte is compared against the output of some gross function pointer return and if any of those comparisons are wrong it will print "Incorrect credentials". 

All of the functions are just there in the binary if you wanted to reverse it manually but I do not. The thing is that every byte of the flag is in memory at some point so all you need to is feed it some placeholder flag and then extract each comparison byte. 

## solve

I solved it using Qiling. I provided it a fake file and hooked the comparison instruction to log the register the byte of the flag was stored in -- ecx. 

```python
from qiling import *
from qiling.os.mapper import QlFsMappedObject

class fake_flag(QlFsMappedObject):

    def read(self, size):
        return b"A" * 20

    def fstat(self): # syscall fstat will ignore it if return -1
        return -1

    def close(self):
        return 0


compared = ""

def log_ecx(ql):
    global compared
    compared += chr(ql.reg.ecx)

ql = Qiling(["./vault"], rootfs="/home/sky/tools/qiling/examples/rootfs/x8664_linux", console=False)

ql.add_fs_mapper('flag.txt', fake_flag())

ql.hook_address(log_ecx, 0x555555554000 + 0xc3a1) # rebase!

ql.run()

print(f"found flag = \"{compared}\"")
```

```text
❯ python3 ./solve.py
Incorrect Credentials - Anti Intruder Sequence Activated...
found flag = "HTB{vt4bl3s_4r3_c00l_huh}"
```

# pneumatic validator


```text
In some alternate reality, computers are not electronics-based but instead use air pressure. No electrons are zipping by and instead, a large pneumatic circuit takes care of all the math. In that world, we reverse engineers are not staring countless hours into debuggers and disassemblers but are inspecting the circuits on a valve level, trying to figure out how the particles will behave in weird components and how they are connected. Thinking about it, that doesn't sound too different, does it? 
```
[pneumaticvalidator](/ctf/htb-uni-quals-2021/pneumaticvalidator)

## reversing

```c
undefined8 main(int argc,char **argv)

{
  undefined8 uVar1;
  size_t sVar2;
  float fVar3;
  int local_10;
  
  puts("Starting the Pneumatic Flag Validation Machine...");
  if (argc == 2) {
    sVar2 = strlen(argv[1]);
    if (sVar2 == 0x14) {
      FUN_00105498(argv[1],0x14);
      puts("Initializing Simulation...");
      init_heap();
      FUN_001012bf();
      FUN_0010149a();
      puts("Simulating...");
      for (local_10 = 0; local_10 < 0x400; local_10 = local_10 + 1) {
        simulate();
      }
      fVar3 = find_max();
      if (15.0 <= fVar3) {
        puts("Wrong \\o\\");
      }
      else {
        puts("Correct /o/");
      }
      FUN_0010125a();
      uVar1 = 0;
    }
    else {
      puts("Wrong length");
      uVar1 = 1;
    }
  }
  else {
    puts("Please provide the flag to verify");
    uVar1 = 1;
  }
  return uVar1;
}
```

It takes a flag provided in argv[1] and asserts the length is 20. It'll run a few setup functions to populate global variables and then run a simulator function 0x400 times. This is honestly pretty big and gross and I didn't want to reverse it so I decided to poke around with GDB. 

![=](/ctf/htb-uni-quals-2021/pneumatic_validator_dynamic.png)


Ah, yes, I can actually just do that lmao. ✨ dynamic analysis ✨. 

## solve

```python
from subprocess import run, PIPE
from string import ascii_letters, digits, punctuation
from pwn import *

def check_pw(pw):
    proc = run(f'gdb ./pneumaticvalidator --nx --ex "b *0x0000555555554000+0x5640" --ex "r {pw}" --ex \'x/f $rbp-4\' --batch', stdout=PIPE,shell=True)
    lines = proc.stdout.decode().split("\n")
    return float(lines[-2].split(":\t")[1])

# known = ""
known = "HTB{PN7Um4t1C_l0g1C}"


# initial pass; not fully accurate but it's enough to get the gist and we can try individual characters again later
while len(known) < 20:
    log.info(f"trying with known \"{known}\"")
    pressures = {}
    for i in ascii_letters + digits + "_{}":
        pw = (known + i).ljust(20,"A")
        pressures[i] = check_pw(pw)
    next = min(pressures.items(), key=lambda x: x[1])
    log.info(f"guessing next letter to be \"{next[0]}\" with pressure of {next[1]}")
    known += next[0]


def vary_index(idx, pw):
    pressures = {}
    log.info(f"varying idx = {idx}, char = {known[idx]}")

    for i in ascii_letters + digits:
        pw[idx] = i
        pressure = check_pw("".join(pw))
        pressures[i] = pressure
    print(sorted(pressures.items(), key=lambda x: x[1]))
    return min(pressures.items(), key=lambda x: x[1])


pw = list(known)
for i in range(4,20): # we know HTB{ is correct
    old_pw = [x for x in pw]
    pw[i] = vary_index(i, pw)[0]

    if pw != old_pw:
        log.info(f"found better flag \"{''.join(pw)}\" -> \"{''.join(old_pw)}\"")
```


lmao i don't deserve this HTB{pN3Um4t1C_l0g1C}