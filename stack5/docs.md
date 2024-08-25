
```bash
$ ./stack5 
sadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadfsadf
Segmentation fault
```

```as
(gdb) disas main
Dump of assembler code for function main:
0x080483c4 <main+0>:	push   ebp
0x080483c5 <main+1>:	mov    ebp,esp
0x080483c7 <main+3>:	and    esp,0xfffffff0
0x080483ca <main+6>:	sub    esp,0x50
0x080483cd <main+9>:	lea    eax,[esp+0x10]
0x080483d1 <main+13>:	mov    DWORD PTR [esp],eax
0x080483d4 <main+16>:	call   0x80482e8 <gets@plt>
0x080483d9 <main+21>:	leave  
0x080483da <main+22>:	ret    
End of assembler dump.
```