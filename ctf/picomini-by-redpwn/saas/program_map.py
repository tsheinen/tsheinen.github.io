import os
from tqdm.contrib.concurrent import process_map

def get_base(a):
	base = os.popen("""gdb chall --batch --nx --ex "set disable-randomization off" --ex "b main" --ex "r" --ex "info proc map" | grep "0x0 /home/sky/Dropbox/ctf/picomini-by-redpwn/saas/chall" | tr -s ' ' | cut -d' ' -f2 """).read()
	return int(base,16)

if __name__ == '__main__':
   bases = process_map(get_base, range(0, 100), max_workers=20)
   print("[*] min base: " + hex(min(bases)))
   print("[*] max base: " + hex(max(bases)))
