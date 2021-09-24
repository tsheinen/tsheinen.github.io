+++
title = "Pwn Resources"
date = 2021-09-23

[taxonomies]
tags = ["resources"]
+++

Collection of resources/tools/etc I thought might be useful for pwning. Hope it's useful!

<!-- more -->

note: the level of endorsement we're talking about for (most) of the courses/educational links here is "i saw it, thought it was cool, and found it in my bookmarks when writing this"

This is an eternal WIP; if you have anything you think would be useful that isn't already here you can contact me on discord @ sky#0004. 

## learning

### [nightmare](https://guyinatuxedo.github.io/index.html)
Collection of writeups, sorted and labelled.

### [LiveOverflow's Binary Exploitation Playlist](https://www.youtube.com/watch?v=iyAyN3GFM7A&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)

### [pwn.college](https://pwn.college/)

ASU's Computer Systems Security (CSE466) course, available online. It's pretty solid and starts at a beginner level.

### [phoenix](https://exploit.education/phoenix/)

### [ctf series: binary exploitation](https://bitvijays.github.io/LFC-BinaryExploitation.html)

Good overview of a lot of introductoring binary exploitation concepts; I used this as a reference for quite a while when I was first getting started. 

### [GOT and PLT for pwning](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)

Good blog post on the details behind GOT/PLT/relocations with a particular eye towards using it for binary exploitation.

## practice

### [deus x64](https://deusx64.ai/)

### [pwnable.kr](http://pwnable.kr/)

### [pwnable.tr](https://pwnable.tw/)

### [picoctf](https://picoctf.org/)

## tools

### [pwntools](https://github.com/Gallopsled/pwntools)

"CTF framework and exploit development library"
unimaginably useful and contains a very significant amount of functionality for solving (primarily pwn) CTF challenges

### [gef](https://github.com/hugsy/gef)

GDB extension; adds a lot of generally useful commands but it'd be worth it just for the context TUI it adds

### [ghidra](https://ghidra-sre.org/)

The NSA's reverse engineering tool -- it works very well and is free.

### [libc-database](https://github.com/niklasb/libc-database)
[hosted](https://libc.rip/)

Used to correlate pointer offsets to libc versions; you provide it a set of symbols and their addresses and it will list libc versions which match. hosted is easier to use but may be missing recent or obscure versions

### [ropper](https://github.com/sashs/Ropper)

Searches and lists "ROP gadgets" in a binary

### [one_gadget](https://github.com/david942j/one_gadget)

Searches libc for a "one gadget" and lists constraints; these are single-shot addresses you can jump to and receive a shell if you match the constraint. 

## reference

### [how2heap](https://github.com/shellphish/how2heap)

Dictionary of heap attacks & examples, I check this out every single time I see a heap challenge I don't know how to do. 

### [pivoting around memory](https://www.nickgregory.me/security/2019/04/06/pivoting-around-memory/)

Describes the locations of pointers in one part of memory to another part; useful if you can read memory and need to turn the location of one region into knowledge of other regions. 