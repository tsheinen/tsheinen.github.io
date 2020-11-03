all:
	gcc -m32 -no-pie -Wl,-z,relro,-z,now -o vuln vuln.c
debug:
	gcc -m32 -no-pie -Wl,-z,relro,-z,now -g -o vuln_debug vuln.c
clean:
	rm vuln