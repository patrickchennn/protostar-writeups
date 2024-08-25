GNU gdb (GDB) 7.0.1-debian
Copyright (C) 2009 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i486-linux-gnu".
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>...
Reading symbols from /opt/protostar/bin/stack1...done.
(gdb) disas main
Dump of assembler code for function main:
0x08048464 <main+0>:	push   ebp
0x08048465 <main+1>:	mov    ebp,esp
0x08048467 <main+3>:	and    esp,0xfffffff0
0x0804846a <main+6>:	sub    esp,0x60
0x0804846d <main+9>:	cmp    DWORD PTR [ebp+0x8],0x1 ; the argc must > 1, in other word, there must be an argument besides the program name
0x08048471 <main+13>:	jne    0x8048487 <main+35> ; if the argc is not > 1, *
0x08048473 <main+15>:	mov    DWORD PTR [esp+0x4],0x80485a0 ; *then this happen
0x0804847b <main+23>:	mov    DWORD PTR [esp],0x1
0x08048482 <main+30>:	call   0x8048388 <errx@plt>
0x08048487 <main+35>:	mov    DWORD PTR [esp+0x5c],0x0 ; *else this happen; this instruction push `0x0` in adresss `esp+0x5c`, there is a probably a variable that is `0` in it
0x0804848f <main+43>:	mov    eax,DWORD PTR [ebp+0xc] ; move address `ebp+0xc`, probably our argument, into `eax`
0x08048492 <main+46>:	add    eax,0x4 ; add address `ebp+0xc` with `0x4`
0x08048495 <main+49>:	mov    eax,DWORD PTR [eax] ; mov address `ebp+0xc+0x4` to `eax`
0x08048497 <main+51>:	mov    DWORD PTR [esp+0x4],eax ; mov that `ebp+0xc+0x4` to `esp+0x4`
0x0804849b <main+55>:	lea    eax,[esp+0x1c]
0x0804849f <main+59>:	mov    DWORD PTR [esp],eax
0x080484a2 <main+62>:	call   0x8048368 <strcpy@plt>
0x080484a7 <main+67>:	mov    eax,DWORD PTR [esp+0x5c]
0x080484ab <main+71>:	cmp    eax,0x61626364 ; compare `esp+0x5c` with some constant `0x61626364`
0x080484b0 <main+76>:	jne    0x80484c0 <main+92> ; Jump Not Equal, **
0x080484b2 <main+78>:	mov    DWORD PTR [esp],0x80485bc ; **equal
0x080484b9 <main+85>:	call   0x8048398 <puts@plt> ; ""
0x080484be <main+90>:	jmp    0x80484d5 <main+113>
0x080484c0 <main+92>:	mov    edx,DWORD PTR [esp+0x5c] ; **not equal
0x080484c4 <main+96>:	mov    eax,0x80485f3
0x080484c9 <main+101>:	mov    DWORD PTR [esp+0x4],edx
0x080484cd <main+105>:	mov    DWORD PTR [esp],eax
0x080484d0 <main+108>:	call   0x8048378 <printf@plt> "Try again, you got {x}", `x` is an hexadecimal of an ASCII character
0x080484d5 <main+113>:	leave  
0x080484d6 <main+114>:	ret    
End of assembler dump.
---

some questions:

1. what's inside `ebp+0x8`?
1. on `main+46` why it get incremented with `0x4`?