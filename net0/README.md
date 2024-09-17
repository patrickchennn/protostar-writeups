In this [net0 protostar](https://exploit.education/protostar/net-zero/) challenge we are expected to send some data thourgh some stdin, and it will be matched with some random generated number. If it's matched, we passed the challenge. Here is the full source code:
```c
#include "../common/common.c"

#define NAME "net0"
#define UID 999
#define GID 999
#define PORT 2999

void run() {
  unsigned int i;
  unsigned int wanted;

  wanted = random();

  printf("Please send '%d' as a little endian 32bit int\n", wanted);

  if(fread(&i, sizeof(i), 1, stdin) == NULL) {
      errx(1, ":(\n");
  }

  if(i == wanted) {
      printf("Thank you sir/madam\n");
  } else {
      printf("I'm sorry, you sent %d instead\n", i);
  }
}

int main(int argc, char **argv, char **envp) {
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  /* Don't do this :> */
  srandom(time(NULL));

  run();
}
```

It's a quite easy challenge because we just need to match our input with the random generated number. However we will do more than that. You see we were given some function that we don't really have access to its source code:
```c
int fd;
background_process(NAME, UID, GID); 
fd = serve_forever(PORT);
set_io(fd);
```

So we will do some background checking, tracking their syscalls, and trying to understand what going on in the background.  

## Reading The Source Code

We know there are some functions that we don't know what it does, `background_process`, `serve_forever`, `set_io`. However, there is a `run()` function. In that function, it generates some random number:
```c
unsigned int wanted;
wanted = random();
```

And then it prints a message to instruct us to give send some data with little endian 32 bit format, and the random number revelead:
```c
printf("Please send '%d' as a little endian 32bit int\n", wanted);
```

It gets data from user thourgh stdin, store it on variable `i`:
```c
fread(&i, sizeof(i), 1, stdin)
```

Lastly the stdin data `i` gets checked with `wanted`:
```c
if(i == wanted) {
    printf("Thank you sir/madam\n");
} else {
    printf("I'm sorry, you sent %d instead\n", i);
}
```


## Running The Program

When we ran the program, it seems didn't do anything.
```bash
user@protostar:/opt/protostar/bin$ ./net0 
user@protostar:/opt/protostar/bin$ 
```

But when examining it through `ps`, it program process was there:
```bash
ps aux | grep net0
999       1498  0.0  0.0   1532   272 ?        Ss   09:21   0:00 /opt/protostar/bin/net0
user      1645  0.0  0.1   3300   732 pts/0    S+   09:52   0:00 grep net0
```

Switch to root `su root` with password `godmode`, and kill the process:

```bash
user@protostar:/opt/protostar/bin$ su root
Password: 
root@protostar:/opt/protostar/bin# kill 1498
root@protostar:/opt/protostar/bin# ps aux | grep net0
root      1650  0.0  0.1   3296   728 pts/0    S+   09:54   0:00 grep net0
```

But if we run again the program, and see the process table (`ps`), the program appeared:
```bash
user@protostar:/opt/protostar/bin$ ./net0 
user@protostar:/opt/protostar/bin$ ps aux | grep net0
999       1655  0.0  0.0   1532   276 ?        Ss   09:55   0:00 ./net0
user      1657  0.0  0.1   3296   728 pts/0    S+   09:55   0:00 grep net0
```
So what's going on here?

```c
/* Run the process as a daemon */
background_process(NAME, UID, GID);
```
That function, as the comment written, it runs something as a background process with several macros passed as arguments. The comment says: `/* Run the process as a daemon */`. Well, what does that even mean? Here's what I got, and I just copied from wikipedia: "*in multitasking computer operating systems, a *daemon* is a computer program that runs as a background process, rather than being under the direct control of an interactive user*". So, there is something in the back, but we still don't what it is exactly.

Also, the program is weirdly run by `USER=999` which it doesn't even exist in the system, do `cat /etc/passwd | grep 999` it will result nothing.

To get more info about the program, we run `strace`:
```bash
$ strace ./net0
execve("./net0", ["./net0"], [/* 24 vars */]) = 0
brk(0)                                  = 0x804b000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7fe0000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=13796, ...}) = 0
mmap2(NULL, 13796, PROT_READ, MAP_PRIVATE, 3, 0) = 0xb7fdc000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\320m\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1319176, ...}) = 0
mmap2(NULL, 1329480, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xb7e97000
mprotect(0xb7fd5000, 4096, PROT_NONE)   = 0
mmap2(0xb7fd6000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x13e) = 0xb7fd6000
mmap2(0xb7fd9000, 10568, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xb7fd9000
close(3)                                = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7e96000
set_thread_area({entry_number:-1 -> 6, base_addr:0xb7e966c0, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0
mprotect(0xb7fd6000, 8192, PROT_READ)   = 0
mprotect(0xb7ffe000, 4096, PROT_READ)   = 0
munmap(0xb7fdc000, 13796)               = 0
rt_sigaction(SIGCHLD, {0x8048dc4, [CHLD], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGPIPE, {SIG_IGN, [PIPE], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
open("/opt/protostar/run/net0.pid", O_RDWR|O_CREAT|O_TRUNC, 0700) = 3
setgroups32(1, [999])                   = 0
setresgid32(999, 999, 999)              = 0
setresuid32(999, 999, 999)              = 0
clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xb7e96728) = 1540
exit_group(0)                           = ?
```
The program will do all the necessary syscalls in order to make the program run like `execve`, `mmap2`, `brk`, and etc. However there are several interesting calls, and we will just focus on some important part of it:

### 1. `open` System Call:

`open("/opt/protostar/run/net0.pid", O_RDWR|O_CREAT|O_TRUNC, 0700) = 3`

1. **File Path**: `"/opt/protostar/run/net0.pid"`
   - This is the path to the file that the program is trying to open.

2. **Flags**: `O_RDWR|O_CREAT|O_TRUNC`
   - These flags specify how the file should be opened and manipulated:
   
   - **`O_RDWR`**: Open the file for both reading and writing.
   - **`O_CREAT`**: If the file does not exist, create it.
   - **`O_TRUNC`**: If the file already exists, truncate it (i.e., erase its content, setting its size to zero).

3. **Mode**: `0700`
   - This is the file permission mode used when creating the file (due to the `O_CREAT` flag). The mode `0700` is an octal representation of the permissions:
     - **Owner (User) Permissions**: `7` (read, write, and execute)
     - **Group Permissions**: `0` (no permissions)
     - **Other Permissions**: `0` (no permissions)

4. **Return Value**: `= 3`
   - The `open` system call returns a file descriptor, which is a non-negative integer representing the opened file. In this case, it returns `3`, meaning the file was successfully opened, and the file descriptor `3` can be used for subsequent read/write operations on this file.

### 2. `setgroups32`, `setresgid32`, and `setresuid32`
The `setgroups32`, `setresgid32`, and `setresuid32` system calls are used to change the user and group identity of a process in Linux. Here's what each of these calls does:

1. **`setgroups32(1, [999]) = 0`**:
   - This system call sets the list of supplementary group IDs for the current process. In this case, it sets the process to belong to only one group, with group ID `999`.
   - `setgroups32` is a version of `setgroups` that handles group IDs using 32-bit integers (useful for compatibility with older systems).
   - `1` indicates the number of groups being set, and `[999]` is the array of group IDs. Here, it's setting the supplementary group to just one ID, `999`.

2. **`setresgid32(999, 999, 999) = 0`**:
   - This system call sets the real, effective, and saved group ID of the process to `999`.
   - The three arguments to `setresgid32` are the real GID, the effective GID, and the saved set-group-ID, all set to `999` in this case.
   - Setting all three to `999` means the process will have a group identity of `999` and will execute with the permissions associated with that group.

3. **`setresuid32(999, 999, 999) = 0`**:
   - This system call sets the real, effective, and saved user ID of the process to `999`.
   - Similar to `setresgid32`, the three arguments represent the real UID, effective UID, and saved set-user-ID. All are being set to `999`.
   - This essentially changes the user identity of the process to UID `999`, and it will execute with the permissions associated with that user.

#### Why is this Done?

Changing the UID and GID of a process is a common technique to drop privileges. For example, a server application might start as the `root` user to bind to a privileged port, but after that, it will change to a less privileged user (e.g., UID `999`) to limit the damage that could be done if the process were compromised.

In our `strace` output, these calls suggest that the `net0` program is intentionally setting its user and group IDs to a less privileged user (`999`) after performing some initial setup, likely for security reasons.

### 3. `clone` call

1. **`clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xb7e96728) = 1540`**:
   - This `clone()` call is creating a new process or thread. 
   - The `flags` argument controls how the new process is created. Here's a breakdown of the flags:
     - **`CLONE_CHILD_CLEARTID`**: When the child exits, the kernel will clear the `child_tidptr` value.
     - **`CLONE_CHILD_SETTID`**: Sets the child’s thread ID at the location pointed to by `child_tidptr`.
     - **`SIGCHLD`**: When the child process exits, the parent will receive a `SIGCHLD` signal, informing it that the child has terminated.
   - The return value of `1540` is the process ID (PID) of the newly created child process.
   - Since the `child_stack` is `0`, this indicates that the child process inherits the parent's stack, which is typical for creating a new process in this manner.

If we take a look at the `man clone` manual page, it says: "_create a new ('child') process, in a manner similar to fork(2)_". So the `clone` system call is used to create a new process or thread in Linux, similar to `fork`, but with more control over what resources are shared between the parent and child processes. It is highly versatile and is often used to create threads in multithreaded applications. It returns the process ID (PID) of the child process, which in this case is `1540`. This value matches the output of `cat /opt/protostar/run/net0.pid`, indicating that the PID of the new process was written to this file.

```bash
$ cat /opt/protostar/run/net0.pid
1540
```

### 4. `exit_group(0)`
The `clone()` and `exit_group()` system calls in your `strace` output are related to the creation of a new process (or thread) and the termination of the parent process.


2. **`exit_group(0) = ?`**:
   - The `exit_group()` system call terminates all threads in a process or process group. In this case, it terminates the parent process (the original one that called `clone()`).
   - The argument `0` indicates the exit status code, where `0` usually signifies a successful termination.
   - The `= ?` means that the `strace` output doesn't show the result of the `exit_group()` call because the process terminates, so there is no return value logged after it.


#### What Happens Here?

1. The `clone()` call creates a child process (PID `1540`).
2. The parent process then calls `exit_group(0)`, terminating itself and possibly other threads it created.
3. The child process (PID `1540`) is now the running process, and it will continue execution independently.

This is a common pattern for programs that fork off a child process and immediately terminate the parent, allowing the child to continue running in the background (a common daemonization technique). By using `exit_group()`, the parent process ensures that it and any threads it created are terminated cleanly.

### Orphan Process
If a parent process terminates after creating a child process (via `clone()` or `fork()`), and the child process is still running, that child process is referred to as an *orphan process*. In such cases, the orphaned child process is reparented to the `init` process (PID 1) or a similar process (depending on the system) which takes over the responsibility of cleaning up the child’s resources when it terminates.

In our `strace` output:
1. The parent process creates a child process using `clone()`.
2. The parent process immediately calls `exit_group(0)` to terminate itself.
   
At this point, the child process (PID 1540) becomes an orphan because its parent has exited. As a result, the operating system will reassign the child to a new parent (usually the `init` process). This is how orphan processes are handled, preventing them from becoming "zombies" (processes that have terminated but still have entries in the process table).


## `strace -f`
Run `strace` again with the following `-f` to list the child processes:
```bash
$ strace -f ./net0
execve("./net0", ["./net0"], [/* 24 vars */]) = 0
brk(0)                                  = 0x804b000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7fe0000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=13796, ...}) = 0
mmap2(NULL, 13796, PROT_READ, MAP_PRIVATE, 3, 0) = 0xb7fdc000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\320m\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1319176, ...}) = 0
mmap2(NULL, 1329480, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xb7e97000
mprotect(0xb7fd5000, 4096, PROT_NONE)   = 0
mmap2(0xb7fd6000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x13e) = 0xb7fd6000
mmap2(0xb7fd9000, 10568, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xb7fd9000
close(3)                                = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7e96000
set_thread_area({entry_number:-1 -> 6, base_addr:0xb7e966c0, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0
mprotect(0xb7fd6000, 8192, PROT_READ)   = 0
mprotect(0xb7ffe000, 4096, PROT_READ)   = 0
munmap(0xb7fdc000, 13796)               = 0
rt_sigaction(SIGCHLD, {0x8048dc4, [CHLD], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGPIPE, {SIG_IGN, [PIPE], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
open("/opt/protostar/run/net0.pid", O_RDWR|O_CREAT|O_TRUNC, 0700) = 3
setgroups32(1, [999])                   = 0
setresgid32(999, 999, 999)              = 0
setresuid32(999, 999, 999)              = 0
clone(Process 1551 attached
child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xb7e96728) = 1551
[pid  1550] exit_group(0)               = ?
    setsid()                                = 1551
    chdir("/")                              = 0
    open("/dev/null", O_RDWR)               = 4
    fstat64(4, {st_mode=S_IFCHR|0666, st_rdev=makedev(1, 3), ...}) = 0
    dup2(4, 0)                              = 0
    dup2(4, 1)                              = 1
    dup2(4, 2)                              = 2
    close(4)                                = 0
    write(3, "1551\n", 5)                   = 5
    close(3)                                = 0
    socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
    setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
    bind(3, {sa_family=AF_INET, sin_port=htons(2999), sin_addr=inet_addr("0.0.0.0")}, 16) = -1 EADDRINUSE (Address already in use)
    write(2, "serve_forever: unable to bind():"..., 56) = 56
    exit_group(6)                           = ?
    Process 1551 detached
```
- The subsequent lines show the child process (`[pid 1551]`) executing various system calls:
    - **`exit_group(0)`**: The parent process (`[pid 1550]`) calls `exit_group(0)` to terminate.
    - **`setsid()`**: The child process becomes the leader of a new session, detaching from the terminal.
    - **`chdir("/")`**: Changes the current working directory to the root (`/`).
    - **`open("/dev/null", O_RDWR)`**: Opens `/dev/null` for reading and writing.
    - **`dup2(4, 0)`, `dup2(4, 1)`, `dup2(4, 2)`**: Redirects the standard input, output, and error (file descriptors `0`, `1`, and `2`) to `/dev/null`.
    - **`socket()`**: Creates a new socket.
    - **`setsockopt()`**: Sets socket options, such as `SO_REUSEADDR`.
    - **`bind()`**: Attempts to bind the socket to address `0.0.0.0:2999`, which fails with `EADDRINUSE`, meaning the address is already in use.
    - **`write()`**: Writes error messages to file descriptor `2` (stderr).
    - **`exit_group(6)`**: The child process exits with status code `6`.

## Socket

### 1. `socket()`

The `socket()` system call is used to create a new socket, which is an endpoint for communication. Sockets are fundamental to network programming and are used to establish a connection between two machines (or processes) over a network.

- **Syntax**: 
  ```c
  int socket(int domain, int type, int protocol);
  ```
- **Parameters**:
  - `domain`: Specifies the communication domain. In your example, `PF_INET` (or `AF_INET`) is used, which stands for the Internet Protocol (IPv4).
  - `type`: Specifies the socket type. `SOCK_STREAM` is used in this case, which provides a sequenced, reliable, two-way, connection-based byte stream. This is typically used for TCP (Transmission Control Protocol) connections.
  - `protocol`: Specifies the protocol to be used. `IPPROTO_IP` (or `0`) is commonly used to indicate that the system should choose the default protocol for the socket type; for `SOCK_STREAM`, this would be TCP.

- **Return Value**: 
  - On success, it returns a non-negative integer, which is the file descriptor for the new socket (e.g., `3` in your example). On failure, it returns `-1` and sets `errno` to indicate the error.

### 2. `setsockopt()`

The `setsockopt()` system call is used to set options on the socket. This is often used to modify the behavior of the socket at the API level.

- **Syntax**:
  ```c
  int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
  ```
- **Parameters**:
  - `sockfd`: The socket file descriptor returned by the `socket()` call (e.g., `3`).
  - `level`: Specifies the protocol level at which the option resides. `SOL_SOCKET` is used for socket-level options.
  - `optname`: The name of the option. `SO_REUSEADDR` is used in this case, which allows the socket to bind to an address that is in a `TIME_WAIT` state (after a previous socket bound to the same address has been closed).
  - `optval`: A pointer to the option value. In your example, `[1]` means the `SO_REUSEADDR` option is enabled.
  - `optlen`: The size of the option value.

- **Return Value**:
  - On success, `setsockopt()` returns `0`. On error, it returns `-1` and sets `errno`.

### 3. `bind()`

The `bind()` system call is used to bind a socket to a specific address and port, which is necessary for server sockets that need to listen for incoming connections.

- **Syntax**:
  ```c
  int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  ```
- **Parameters**:
  - `sockfd`: The socket file descriptor returned by `socket()`.
  - `addr`: A pointer to a `sockaddr` structure that contains the address and port to bind to. In your example, the `sockaddr_in` structure specifies:
    - `sa_family=AF_INET`: The address family (IPv4).
    - `sin_port=htons(2999)`: The port number, which is converted to network byte order using `htons()` (host to network short).
    - `sin_addr=inet_addr("0.0.0.0")`: The IP address to bind to. `0.0.0.0` means "bind to all available interfaces."
  - `addrlen`: The length of the address structure.

- **Return Value**:
  - On success, `bind()` returns `0`. On failure, it returns `-1` and sets `errno`.

- **Error in Your Case (`EADDRINUSE`)**:
  - The `bind()` call fails with `EADDRINUSE` (Address already in use). This means that another socket is already bound to the same address (`0.0.0.0:2999`). This can happen if another instance of the application is already running or another process has bound to that address and port.

To summarize:
- **`socket()`**: Creates a socket that can be used for communication.
- **`setsockopt()`**: Modifies the socket's options, such as allowing the reuse of local addresses (`SO_REUSEADDR`).
- **`bind()`**: Associates the socket with a specific IP address and port. If `EADDRINUSE` is encountered, it indicates that the address and port are already in use by another socket.

These three system calls are commonly used together when setting up a server socket to listen for incoming connections on a specified IP address and port.

## Rerun The Program
So the port `2999` somehow was already in used, we kill all the proccess that associated with `net0`, and run the `strace` again:
```bash
$ killall net0
$ strace -f ./net0
execve("./net0", ["./net0"], [/* 24 vars */]) = 0
brk(0)                                  = 0x804b000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7fe0000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=13796, ...}) = 0
mmap2(NULL, 13796, PROT_READ, MAP_PRIVATE, 3, 0) = 0xb7fdc000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\320m\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1319176, ...}) = 0
mmap2(NULL, 1329480, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xb7e97000
mprotect(0xb7fd5000, 4096, PROT_NONE)   = 0
mmap2(0xb7fd6000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x13e) = 0xb7fd6000
mmap2(0xb7fd9000, 10568, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xb7fd9000
close(3)                                = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7e96000
set_thread_area({entry_number:-1 -> 6, base_addr:0xb7e966c0, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0
mprotect(0xb7fd6000, 8192, PROT_READ)   = 0
mprotect(0xb7ffe000, 4096, PROT_READ)   = 0
munmap(0xb7fdc000, 13796)               = 0
rt_sigaction(SIGCHLD, {0x8048dc4, [CHLD], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGPIPE, {SIG_IGN, [PIPE], SA_RESTART}, {SIG_DFL, [], 0}, 8) = 0
open("/opt/protostar/run/net0.pid", O_RDWR|O_CREAT|O_TRUNC, 0700) = 3
setgroups32(1, [999])                   = 0
setresgid32(999, 999, 999)              = 0
setresuid32(999, 999, 999)              = 0
clone(Process 1557 attached
child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xb7e96728) = 1557
[pid  1556] exit_group(0)               = ?
setsid()                                = 1557
chdir("/")                              = 0
open("/dev/null", O_RDWR)               = 4
fstat64(4, {st_mode=S_IFCHR|0666, st_rdev=makedev(1, 3), ...}) = 0
dup2(4, 0)                              = 0
dup2(4, 1)                              = 1
dup2(4, 2)                              = 2
close(4)                                = 0
write(3, "1557\n", 5)                   = 5
close(3)                                = 0
socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
bind(3, {sa_family=AF_INET, sin_port=htons(2999), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
listen(3, 10)                           = 0
accept(3, 
```
We end up with `accept` calls where it seems waiting for something.

### What is `accept()`?

Here is what the `man accept` said:
> The  accept()  system call is used with connection-based socket types (SOCK_STREAM, SOCK_SEQPACKET). It extracts the first connection request on the queue of pending connections for the listening socket, sockfd, creates a new connected socket, and returns a new file descriptor referring to that socket. The newly created socket is not in the listening state. The original socket sockfd is unaffected by this call.

- **Purpose**: `accept()` is used by a server to accept an incoming connection request from a client. It blocks the server's process until a connection attempt is made by a client, making the server "listen" for connections.
- **Syntax**:
  ```c
  int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  ```
- **Parameters**:
  - `sockfd`: The listening socket file descriptor (in our case, `3`), which was returned by the `socket()` call and associated with an address using `bind()`.
  - `addr`: A pointer to a `sockaddr` structure that will hold the address information of the connecting client.
  - `addrlen`: A pointer to a variable that holds the size of the `addr` structure. It is used to return the size of the client address.

- **Return Value**:
  - On success, `accept()` returns a new socket file descriptor that represents the established connection with the client. This socket is used for communication with the connected client.
  - On error, it returns `-1` and sets `errno`.

### What Happens After `accept()`?

When the `accept()` call is made, the following events occur:
1. **Waiting for a Client**: The server waits for a client to attempt to connect to it. During this time, `accept()` is blocking, meaning the program will not proceed further until a client connection request is detected.
   
2. **New Socket Creation**: When a client connects, `accept()` creates a new socket for that specific client connection and returns a file descriptor for this new socket. The original socket (in our case, `sockfd = 3`) remains open and continues to listen for more incoming connections.

3. **Communication**: The server can then use the new socket descriptor returned by `accept()` to send and receive data to and from the connected client.

### The `strace` Output

From the `strace` output, we can see the following sequence leading to `accept()`:

1. **Socket Creation**: `socket(PF_INET, SOCK_STREAM, IPPROTO_IP)` creates a TCP socket.
2. **Setting Socket Options**: `setsockopt()` is called to set the `SO_REUSEADDR` option.
3. **Binding to an Address and Port**: `bind()` binds the socket to address `0.0.0.0` (all network interfaces) and port `2999`.
4. **Listening for Connections**: `listen(3, 10)` makes the socket listen for incoming connections, with a backlog queue size of 10.
5. **Waiting for Client Connection**: `accept(3, ...)` is waiting for an incoming client connection. Since `accept()` is blocking, our program will remain here until a client attempts to connect to the server.

### Why is `accept()` Important?

- **Blocking Behavior**: The `accept()` function is blocking, which means it will halt the server's execution until a client connection is detected. If you want a non-blocking behavior, you can use `select()`, `poll()`, or `epoll()` with non-blocking sockets.
- **Handling Multiple Clients**: If our server is designed to handle multiple clients, you'll typically need to use `fork()`, `pthread_create()`, or some other concurrency mechanism after `accept()` to handle each client connection independently.

So, the `accept()` call is waiting for a client to connect to our server. If no client attempts to connect, the program will remain blocked at this call. This is normal behavior for a server application that waits for incoming connections.


## `netstat -plant`

```bash
$ netstat -plant
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      918/portmap     
tcp        0      0 0.0.0.0:2993            0.0.0.0:*               LISTEN      1469/final2     
tcp        0      0 0.0.0.0:2994            0.0.0.0:*               LISTEN      1467/final1     
tcp        0      0 0.0.0.0:2995            0.0.0.0:*               LISTEN      1465/final0     
tcp        0      0 0.0.0.0:2996            0.0.0.0:*               LISTEN      1463/net3       
tcp        0      0 0.0.0.0:2997            0.0.0.0:*               LISTEN      1461/net2       
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1594/sshd       
tcp        0      0 0.0.0.0:2998            0.0.0.0:*               LISTEN      1459/net1       
tcp        0      0 0.0.0.0:2999            0.0.0.0:*               LISTEN      1557/net0       
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      1438/exim4      
tcp        0      0 0.0.0.0:48606           0.0.0.0:*               LISTEN      930/rpc.statd   
tcp        0      0 10.7.120.206:22         10.7.120.194:36026      ESTABLISHED 1603/sshd: user [pr
tcp        0      0 10.7.120.206:22         10.7.120.194:46192      ESTABLISHED 1673/sshd: user [pr
tcp6       0      0 :::22                   :::*                    LISTEN      1594/sshd       
tcp6       0      0 ::1:25                  :::*                    LISTEN      1438/exim4      
```
On port 2999 the process `net0` is listening.

## netcat

Netcat is operating in client mode by default (when no -l or -p option is specified), which means it is trying to connect to the specified IP address (127.0.0.1) on the given port (2999).
```bash
$ nc 127.0.0.1 2999
Please send '1320606901' as a little endian 32bit int
```

After there is a client connected, the `strace` will give this respond:
```bash
 {sa_family=AF_INET, sin_port=htons(59323), sin_addr=inet_addr("127.0.0.1")}, [16]) = 4
clone(Process 1724 attached
child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xb7e96728) = 1724
[pid  1718] close(4)                    = 0
[pid  1718] accept(3,  <unfinished ...>
[pid  1724] close(3)                    = 0
[pid  1724] dup2(4, 0)                  = 0
[pid  1724] dup2(4, 1)                  = 1
[pid  1724] dup2(4, 2)                  = 2
[pid  1724] time(NULL)                  = 1726248252
[pid  1724] write(1, "Please send '1320606901' as a li"..., 54) = 54
[pid  1724] read(0, 
```
1. The `write` call seems correspond with `printf("Please send '%d' as a little endian 32bit int\n", wanted);`
2. It end up with `read` which it seems correlated with `fread(&i, sizeof(i), 1, stdin) == NULL`.

So we are expected to give stdin into that program, now back to the netcat, and let's send some data `1234`:
```bash
1234
I'm sorry, you sent 875770417 instead
```
The last line was the message we got.


Updated `strace`:
```bash
 "1234", 4)          = 4
[pid  1724] write(1, "I'm sorry, you sent 875770417 in"..., 38) = 38
[pid  1724] exit_group(38)              = ?
Process 1724 detached
<... accept resumed> 0xbffff6b8, [16])  = ? ERESTARTSYS (To be restarted)
--- SIGCHLD (Child exited) @ 0 (0) ---
wait4(-1, [{WIFEXITED(s) && WEXITSTATUS(s) == 38}], 0, NULL) = 1724
sigreturn()                             = ? (mask now [])
accept(3, 
```

So connect to that port again using netcat. This time we using a little trick:
```bash
echo -e "`cat -`" | nc 127.0.0.1 2999
Please send '1482374427' as a little endian 32bit int
```

Updated `strace`:
```bash
{sa_family=AF_INET, sin_port=htons(59327), sin_addr=inet_addr("127.0.0.1")}, [16]) = 4
clone(Process 1740 attached
child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xb7e96728) = 1740
[pid  1718] close(4)                    = 0
[pid  1718] accept(3,  <unfinished ...>
[pid  1740] close(3)                    = 0
[pid  1740] dup2(4, 0)                  = 0
[pid  1740] dup2(4, 1)                  = 1
[pid  1740] dup2(4, 2)                  = 2
[pid  1740] time(NULL)                  = 1726248947
[pid  1740] write(1, "Please send '1482374427' as a li"..., 54) = 54
[pid  1740] read(0
```

Constructing the correct data, and sending it:
```py
>>> struct.pack("I",1482374427)
b'\x1b=[X'
```

And here is the response:
```bash
Thank you sir/madam
```

```bash
 "\33=[X", 4)        = 4
[pid  1740] write(1, "Thank you sir/madam", 19) = 19
[pid  1740] write(1, "\n", 1)           = 1
[pid  1740] exit_group(20)              = ?
Process 1740 detached
<... accept resumed> 0xbffff6b8, [16])  = ? ERESTARTSYS (To be restarted)
--- SIGCHLD (Child exited) @ 0 (0) ---
wait4(-1, [{WIFEXITED(s) && WEXITSTATUS(s) == 20}], 0, NULL) = 1740
sigreturn()                             = ? (mask now [])
accept(3,
```

So we passed the challenge.

## Conclusion
We learn reversing the program step by step, socket programming in C, connecting to server using `nc`.

## Resources

https://www.youtube.com/watch?v=2CL-AAcgyuo&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=33