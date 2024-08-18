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