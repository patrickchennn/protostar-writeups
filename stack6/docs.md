
```as
(gdb) disas main
Dump of assembler code for function main:
0x080484fa <main+0>:	push   ebp
0x080484fb <main+1>:	mov    ebp,esp
0x080484fd <main+3>:	and    esp,0xfffffff0
0x08048500 <main+6>:	call   0x8048484 <getpath>
0x08048505 <main+11>:	mov    esp,ebp
0x08048507 <main+13>:	pop    ebp
0x08048508 <main+14>:	ret    
End of assembler dump.

(gdb) disas getpath
Dump of assembler code for function getpath:
0x08048484 <getpath+0>:	push   ebp
0x08048485 <getpath+1>:	mov    ebp,esp
0x08048487 <getpath+3>:	sub    esp,0x68
0x0804848a <getpath+6>:	mov    eax,0x80485d0 ; "input path please: "
0x0804848f <getpath+11>:	mov    DWORD PTR [esp],eax
0x08048492 <getpath+14>:	call   0x80483c0 <printf@plt>
0x08048497 <getpath+19>:	mov    eax,ds:0x8049720
0x0804849c <getpath+24>:	mov    DWORD PTR [esp],eax
0x0804849f <getpath+27>:	call   0x80483b0 <fflush@plt>
0x080484a4 <getpath+32>:	lea    eax,[ebp-0x4c]
0x080484a7 <getpath+35>:	mov    DWORD PTR [esp],eax
0x080484aa <getpath+38>:	call   0x8048380 <gets@plt>
0x080484af <getpath+43>:	mov    eax,DWORD PTR [ebp+0x4]
0x080484b2 <getpath+46>:	mov    DWORD PTR [ebp-0xc],eax
0x080484b5 <getpath+49>:	mov    eax,DWORD PTR [ebp-0xc]
0x080484b8 <getpath+52>:	and    eax,0xbf000000
0x080484bd <getpath+57>:	cmp    eax,0xbf000000
0x080484c2 <getpath+62>:	jne    0x80484e4 <getpath+96>
0x080484c4 <getpath+64>:	mov    eax,0x80485e4 ; "bzzzt (%p)\n"
0x080484c9 <getpath+69>:	mov    edx,DWORD PTR [ebp-0xc]
0x080484cc <getpath+72>:	mov    DWORD PTR [esp+0x4],edx
0x080484d0 <getpath+76>:	mov    DWORD PTR [esp],eax
0x080484d3 <getpath+79>:	call   0x80483c0 <printf@plt>
0x080484d8 <getpath+84>:	mov    DWORD PTR [esp],0x1
0x080484df <getpath+91>:	call   0x80483a0 <_exit@plt>
0x080484e4 <getpath+96>:	mov    eax,0x80485f0 ; "got path %s\n"
0x080484e9 <getpath+101>:	lea    edx,[ebp-0x4c]
0x080484ec <getpath+104>:	mov    DWORD PTR [esp+0x4],edx
0x080484f0 <getpath+108>:	mov    DWORD PTR [esp],eax
0x080484f3 <getpath+111>:	call   0x80483c0 <printf@plt>
0x080484f8 <getpath+116>:	leave  
0x080484f9 <getpath+117>:	ret    
End of assembler dump.
```

The buffer is start at `ebp` with offset `-0x4c`:
```as
(gdb) x/wx $ebp-0x4c
0xbffff75c:	0xb7f0186e
```

These three instructions:
```as
0x080484af <getpath+43>:	mov    eax,DWORD PTR [ebp+0x4]
0x080484b2 <getpath+46>:	mov    DWORD PTR [ebp-0xc],eax
0x080484b5 <getpath+49>:	mov    eax,DWORD PTR [ebp-0xc]
```
is about this code:
```c
unsigned int ret;
...
ret = __builtin_return_address(0);
```

If we take a look inside `ebp+0x4` is just the return address of `getpath()` function which is this instruction `0x08048505 <main+11>: mov esp,ebp`:
```as
(gdb) x/wx $ebp+0x4
0xbffff7ac:	0x08048505
```
so the `ret` is located at this offset `ebp-0xc`.


```as
(gdb) c
Continuing.
input path please: AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSS
esp            0xbffff740	0xbffff740
ebp            0xbffff7a8	0xbffff7a8
eip            0x80484af	0x80484af <getpath+43>
0xbffff740:	0xbffff75c	0x00000000	0xb7fe1b28	0x00000001
0xbffff750:	0x00000000	0x00000001	0xb7fff8f8	0x41414141
0xbffff760:	0x42424242	0x43434343	0x44444444	0x45454545
0xbffff770:	0x46464646	0x47474747	0x48484848	0x49494949
0xbffff780:	0x4a4a4a4a	0x4b4b4b4b	0x4c4c4c4c	0x4d4d4d4d
0xbffff790:	0x4e4e4e4e	0x4f4f4f4f	0x50505050	0x51515151
0xbffff7a0:	0x52525252	0x53535353	0xbffff700	0x08048505
0xbffff7b0:	0x08048520	0x00000000	0xbffff838	0xb7eadc76
0xbffff7c0:	0x00000001	0xbffff864	0xbffff86c	0xb7fe1848
0xbffff7d0:	0xbffff820	0xffffffff	0xb7ffeff4	0x080482a1
0x80484af <getpath+43>:	mov    eax,DWORD PTR [ebp+0x4]
0x80484b2 <getpath+46>:	mov    DWORD PTR [ebp-0xc],eax
(gdb) 
esp            0xbffff740	0xbffff740
ebp            0xbffff7a8	0xbffff7a8
eip            0x80484b8	0x80484b8 <getpath+52>
0xbffff740:	0xbffff75c	0x00000000	0xb7fe1b28	0x00000001
0xbffff750:	0x00000000	0x00000001	0xb7fff8f8	0x41414141
0xbffff760:	0x42424242	0x43434343	0x44444444	0x45454545
0xbffff770:	0x46464646	0x47474747	0x48484848	0x49494949
0xbffff780:	0x4a4a4a4a	0x4b4b4b4b	0x4c4c4c4c	0x4d4d4d4d
0xbffff790:	0x4e4e4e4e	0x4f4f4f4f	0x50505050	0x08048505
0xbffff7a0:	0x52525252	0x53535353	0xbffff700	0x08048505
0xbffff7b0:	0x08048520	0x00000000	0xbffff838	0xb7eadc76
0xbffff7c0:	0x00000001	0xbffff864	0xbffff86c	0xb7fe1848
0xbffff7d0:	0xbffff820	0xffffffff	0xb7ffeff4	0x080482a1
0x80484b8 <getpath+52>:	and    eax,0xbf000000
0x80484bd <getpath+57>:	cmp    eax,0xbf000000
```


