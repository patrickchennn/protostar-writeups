
## Reading The Source Code
These abstracted functions:
```c
/* Run the process as a daemon */
background_process(NAME, UID, GID); 

/* Wait for socket activity and return */
fd = serve_forever(PORT);

/* Set the client socket to STDIN, STDOUT, and STDERR */
set_io(fd);
```
were already explain on the [previous level](), check it out, it's basically just setting up socket streams.
```c
void run(){
  char buf[12];
  char fub[12];
  char *q;

  unsigned int wanted;

  wanted = random();

  sprintf(fub, "%d", wanted);

  if(write(0, &wanted, sizeof(wanted)) != sizeof(wanted)) {
      errx(1, ":(\n");
  }

  if(fgets(buf, sizeof(buf)-1, stdin) == NULL) {
      errx(1, ":(\n");
  }

  q = strchr(buf, '\r'); if(q) *q = 0;
  q = strchr(buf, '\n'); if(q) *q = 0;

  if(strcmp(fub, buf) == 0) {
      printf("you correctly sent the data\n");
  } else {
      printf("you didn't send the data properly\n");
  }
}
```

---

Generate random number `random()` and store it into `wanted` variable:
```c
unsigned int wanted;
wanted = random()
```

The unusual `printf` function with prefix 's' in it is about store the `wanted` into some buffer `fub` that is located on the stack, and print the value of `wanted`:
```c
char fub[12];
sprintf(fub, "%d", wanted);
```

---

### `write`
```c
if(write(0, &wanted, sizeof(wanted)) != sizeof(wanted)) {
    errx(1, ":(\n");
}
```
- **File descriptor `0` (stdin)**: In a normal situation, `fd = 0` refers to standard input (stdin), which is meant for reading. However, in this program, `stdin`, `stdout`, and `stderr` have been **redirected to the socket** using `set_io(fd)`. So now, `fd = 0` refers to the network socket connected to the client.
  
- **`&wanted, sizeof(wanted)`**: The program is writing the binary data of the `wanted` variable (a random `unsigned int`) to the client. The client receives this number over the network. (later we will see the output when we connect the server as client)

So, **`write(0, &wanted, sizeof(wanted))` is sending the random number to the connected client via the network socket**. It's not writing to stdin in the traditional sense; it's writing to the network socket, which is now file descriptor `0`.

### `fgets` and Comparing with Client Input

After writing the number to the client, the program expects the client to send the same number back. The program reads the response using `fgets`:

```c
if(fgets(buf, sizeof(buf)-1, stdin) == NULL) {
    errx(1, ":(\n");
}
```

Here, `stdin` is now the network socket, so the program is reading the response from the client.

### Comparing the Input
```c
q = strchr(buf, '\r'); if(q) *q = 0;
q = strchr(buf, '\n'); if(q) *q = 0;

if(strcmp(fub, buf) == 0) {
    printf("you correctly sent the data\n");
} else {
    printf("you didn't send the data properly\n");
}
```
- The program removes any newline (`\n`) or carriage return (`\r`) from the string received from the client.
- It then compares the string representation of the original `wanted` number (`fub`) with the string received from the client (`buf`).
- If they match, the program prints "you correctly sent the data." Otherwise, it prints that the client didn’t send the data properly.

### Summary of Flow

1. The server generates a random number (`wanted`).
2. The server sends this random number to the client (via the network socket, which is now file descriptor `0`).
3. The client is expected to send the same number back.
4. The server reads the client's response, compares it with the original number, and prints whether the client responded correctly.

## Connect To Server

Here is one way to connect to the server, we are using python:
```py
import socket
import struct
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ADDR = "127.0.0.1"
PORT = 2998
s.connect((ADDR,PORT))

n = s.recv(4)
print(n)
print(repr(n))
print(n.encode('hex'))

N = struct.unpack("I",n)
print(N)
s.send(str(N[0]))
print(s.recv(1024))
```
And if we run it, it works but sometimes the program hangs:
```bash
user@protostar:/tmp$ python so.py 
;�n 
';\xf4n '
3bf46e20
(544142395,)
^CTraceback (most recent call last):
  File "so.py", line 16, in <module>
    print(s.recv(1024))
KeyboardInterrupt
user@protostar:/tmp$ python so.py 
���)
'\xc1\x84\x80)'
c1848029
(696288449,)
^CTraceback (most recent call last):
  File "so.py", line 16, in <module>
    print(s.recv(1024))
KeyboardInterrupt
user@protostar:/tmp$ python so.py 
��E
'\xeb\xa6\xdeE'
eba6de45
(1172219627,)
you correctly sent the data
```

## `srandom(time(NULL))`

If we execute the program again and again as fast as possible:
```bash
user@protostar:/tmp$ python so.py 
��^
'\x8a\xea\xb0^'
8aeab05e
(1588652682,)
you correctly sent the data
user@protostar:/tmp$ ^C
user@protostar:/tmp$ python so.py 
��^
'\x8a\xea\xb0^'
8aeab05e
(1588652682,)
you correctly sent the data
```
The program generated the same number. That's because, see `main()`, the seed is just the current time `srandom(time(NULL));`, so the seed was possibly the same.

The line `srandom(time(NULL));` is responsible for **seeding** the random number generator used by the program. Let's break it down:

### What `srandom(time(NULL));` Does:

1. **`time(NULL)`**: 
   - This function call returns the current time in seconds since the Unix epoch (January 1, 1970). It changes every second.
   - This value is used as the seed for the random number generator.

2. **`srandom(seed)`**:
   - This function seeds the random number generator with the provided value (in this case, the current time from `time(NULL)`).
   - It is important to seed the random number generator to ensure that it produces different sequences of random numbers each time the program runs.

In theory, every time you run the program, it should generate a different random number because the time is constantly changing.

### Why Seeing the Same Random Number

The fact that we are seeing the **same random number** across multiple executions suggests that the **seed value** (`time(NULL)`) isn't changing between runs, which leads to the random number generator producing the same number repeatedly.

#### Possible Reasons for the Same Seed:

1. **Program Executions in Rapid Succession**:
   - If we are running the program multiple times **within the same second**, `time(NULL)` will return the same value for each run. This results in the same seed being used for `srandom`, causing the program to generate the same random number.
   - Example: If we run the program twice within a second (say at `1588652682` seconds), both executions will generate the same "random" number.

2. **System Time Not Changing**:
   - In rare cases, if the system time isn't updating or if the system clock is "frozen," it could result in `time(NULL)` returning the same value, causing the random number generator to produce the same number.

### Observing the Random Value in Python

The fact that our Python client connected to the server, retrieved the random value (like `8aeab05e`), and printed the same value twice suggests that the server is generating the same random number on each run due to the reasons mentioned above.

### How to Fix This:

To ensure you get different random numbers each time:
- **Wait a second or more** between runs to allow `time(NULL)` to return a different value.
- Alternatively, use a different randomization mechanism, but in most cases, simply waiting a second should resolve this issue.
