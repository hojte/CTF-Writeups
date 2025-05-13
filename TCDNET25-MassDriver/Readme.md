# TCD NET CTF
The TDCNET CTF was a medium level CTF. Not on CTF-time because physical participation was a part of the rules. Players from the danish national team 'Cyberlandsholdet' as well as Kalmarunionen participated and were the main competitors for the 1st place. The even was nicely hosted at TDC NET at their headquarters in Copenhagen.

## Challenge description
Category: reversing
Name: Mass Driver
Author: mad31k

We are currently testing a new mass driver technology designed to deliver payloads to the moon more efficiently than conventional methods. Our engineering team has developed the system, but has misplaced the necessary launch codes required for today's scheduled test. Could you please help initiate our launch sequence? We have a limited window for this test operation.

IMPORTANT NOTE: Due to our engineering team's questionable competence, this launch sequence is specifically designed for our specialized systems only. Please do not attempt to execute this code on your personal machine as our engineers' less-than-stellar work could cause significant system damage. USE VIRTUAL MACHINE!

## TL;DR
1. Find correct IOCTL branch (1337 hint)
2. See that the flag is decrypted using the direct result of one function + some static values and then returned to the client.
3. Supply password (launch code 1) function, `sub_1400015D8()`, and flag decryption func `sub_140002030((__int64)v18, 0x2Bui64, v16, &v22flag, (unsigned __int64 *)v22)` (+ static values v16 and v18) to LLM for emulation in C++.
4. Compile or [run online](https://www.programiz.com/cpp-programming/online-compiler/)

## Initial inspection
We are given a Windows Kernel driver:
```bash
>file MassDriver.sys
MassDriver.sys: PE32+ executable (native) x86-64, for MS Windows, 6 sections
```
A kernel driver can also be recognized from the .sys file extension. It can be loaded and unloaded like this:
```bash
sc create MyDriver type= kernel binPath=C:\Users\Hojte\Downloads\MassDriver.sys
sc start MyDriver
sc stop MyDriver
sc delete MyDriver
```
However, the driver is only signed with a test certificate, therefore, Windows will not allow running it unless booted in testsigning mode:
```bash
bcdedit /set testsigning on
```
And I love patching binaries, so if we want to do that later:
```bash
bcdedit /set nointegritychecks on
```
Lastly, DbgView (Microsoft program) can be nice to use, since it can log the DebugPrint() calls by kernel drivers. Launch it as admin and enable capture:  
**Capture -> Kernel Capture + Enable Verbose Kernel Output**
## Debugging and VM Ware
If debugging is desired, it has to be done on a **Windows Guest VM**. In general it is good practice, as the challenge mentions, to run unstable / untrusted drivers in a VM because of the Admin-like privileges that kernel drivers have. Furthermore, if a kernel driver crashes, it will result in a blue screen (BSoD). This is very bad for productivity, unsaved work and IDA files FYI... Nowadays, theres problems with the evaluation copy of Windows 10/11 specifically made for VM Ware, Vitualbox etc., so the normal Windows ISO will have to do.
### WinDbg over named pipe
Kernel drivers are debugged in WinDbg. You can't debug(break/freeze) your own hosts kernel drivers because they're integral to the function of the host system. 

WinDbg supports Network, USB and Serial debugging. The by far easiest to set up with a VM Ware Guest is Serial debugging:
1. [Guest] `bcdedit /debug on`
2. [Guest] `bcdedit /dbgsettings serial debugport:1 baudrate:115200 /noumex`
3. [Guest] `shutdown -s -t 0`
4. VM Ware -> VM -> Settings -> Add (Serial) -> Use named pipe -> `\\.\pipe\com_port1` -> This end is server -> Other end is Application -> Yield CPU on pull.
5. [Host] WinDbg -> File -> Kernel Debug... -> COM -> Port = `\\.\pipe\com_port1` -> Pipe -> Reconnect.
6. Turn on VM -> If no connection: Make sure the pipe matches -> REBOOT.

WinDbg should now say:
```
Connected to Windows 10 26100 x64 target at (Tue May  6 19:06:55.287 2025 (UTC + 2:00)), ptr64 TRUE
Kernel Debugger connection established.
```
7. [Guest] Load the driver (Use `RunMassDriver.bat`)
8. [Host] WinDbg -> Debug -> Break
9. Run WinDbg command `lm` (list loaded modules)
10. Find MassDriver: 
```
fffff806`633d0000 fffff806`633d8000   MassDriver   (deferred)
```    
11. Now we're ready for debugging!

## IDA Inspection
What is more feasible In a CTF than a big debugging setup, is to simply reverse the binary. All the information is already there, it's probably just obfuscated a bit ;)

### DriverEntry
In kernel development, the entrypoint is not called `main()`, its called `DriverEntry`. This entry has a DriverObject, where the developer can register functions for Unloading the driver safely, or IOCTL handlers, which is the normal way of communicating with drivers from "Userland" - the normal programs. 
```c
__int64 __fastcall sub_1400023A8(PDRIVER_OBJECT DriverObject)
{
  DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_140001C00;
  DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)&sub_140001C60;
  DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)&sub_140001DE0;
  DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)&sub_140001DE0;
  sub_140001E08();
  IoCreateDevice(DriverObject, 0, &DeviceName, 0x22u, 0x100u, 0, &DriverObject->DeviceObject);
  IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
  return 0i64;
}
```
In this chunk, the important parts are:
1. `sub_140001C60` registered as a IOCTL handler
2. `sub_140001E08` is run after registrations/initialization
3. We can follow `SymbolicLinkName` to know the name we can use in our "Userland" client (`\\.\MassDriverDeviceLink`). I initially found it via WinObj from sysinternals, by searching for 'MassDriver'.

### Ready function
Inspecting `sub_140001E08`:
```c
  DbgPrint("    /\\\n");
  DbgPrint("   /  \\\n");
  DbgPrint("  |    |\n");
  DbgPrint("  |MOON|\n");
  DbgPrint("  |    |\n");
  DbgPrint("  |    |\n");
  DbgPrint("  |    |\n");
  DbgPrint(" /      \\\n");
  DbgPrint(" |      |\n");
  DbgPrint(" |      |\n");
  DbgPrint(" |______|\n");
  DbgPrint("  '-```'-`   .\n");
  DbgPrint("  / . \\'\\. .'\n");
  DbgPrint(" ''( .'\\.'' .;'\n");
  DbgPrint("'.;.;' ;'.;' ..;;' AsH\n");
    v0 = 0x6128FA25;
  *(__m128i *)&v11[4] = _mm_load_si128((const __m128i *)&xmmword_1400031A0);
  v1 = -1i64;
  *(_DWORD *)v11 = 0x6128FA25;
  v2 = -1i64;
  *(__m128i *)&v11[36] = _mm_load_si128((const __m128i *)&xmmword_140003160);
  *(__m128i *)&v11[20] = _mm_load_si128((const __m128i *)&xmmword_140003290);
  do
    ++v2;
  while ( v11[v2 + 4] );
  Pool2 = (const CHAR *)ExAllocatePool2(64i64, v2 + 1, 1263752274i64);
  if ( Pool2 )
  {
    v7 = 0i64;
    v10 = 0;
    v4 = 0i64;
    v8 = 0i64;
    v5 = 47i64;
    LODWORD(v7) = 0x6128FA25;
    v9 = 0i64;
    do
    {
      *((_BYTE *)&v7 + v4 + 4) = v11[v4 + 4] ^ v0;
      ++v4;
      v0 = 48271 * v0 % 0x7FFFFFFF;
      --v5;
    }
    while ( v5 );
    *(_DWORD *)&v11[48] = v10;
    *(_OWORD *)v11 = v7;
    *(_OWORD *)&v11[16] = v8;
    *(_OWORD *)&v11[32] = v9;
    do
      ++v1;
    while ( v11[v1 + 4] );
    MEMMOVEsub_140002640(Pool2, &v11[4], v1 + 1);
  }
  return DbgPrint(Pool2); 
  ```
Takeaways:
1. The driver will always print out some ASCII art, we can see this in the DbgView program (and also in WinDbg if connected).
2. After ASCII art another string is printed, based on rather simple XOR decryption of data already embedded in the binary (`xmmword_140003xxx`). The string is `THE MASS DRIVER IS AWAITING THE INSTRUCTIONS.`
3. We most likely need to send some instructions through IOCTL.

### Most interesting branch function
Now we take a look at the **imporatant part** of the IOCTL handler function `__int64 __fastcall sub_140001C60(__int64 a1, IRP *a2)`
```c
LowPart = CurrentStackLocation->Parameters.Read.ByteOffset.LowPart;
if ( LowPart == ((4 * (MEMORY[0xFFFFF78000000008] % 0x22Bui64)) | 0x22000000) )
{
v7 = sub_1400016D8(v11);
}
else if ( LowPart == 322379776 )
{
v7 = sub_140002164((char *)Str);
}
else
{
v7 = sub_140001848(v11);
}
...
IofCompleteRequest(a2, 0); // v7 is a2
```
In cooporation with an LLM, it is easier to get a quick overview of the function. Here is the important part:
1. `Lowpart` is used for some switch, it is reasonable to think that Lowpart will be the `IoControlCode` (in a request - IRP)
2. All the possible functions return a string pointer, which is used for answering the IOCTL request.
3. First function seems to be hard to enter since it is using some dynamic memory region for comparison.
4. Second function matches `0x13372000` with the control code. 1337 is a big hint that this is the function of interest. It also takes in what is most likely the `lpInBuffer` - the payload of the IOCTL request.
5. Must be a fail function. Verified by sending garbage to the driver. (returns `++ INCORRECT TEMPORARY ACCESS CODE ++` to the client)

### The flag return function
Inspction of the second function `__int64 __fastcall sub_140002164(char *Str)`
```c
...
if ( !Str )
    return sub_140001A9C(v18);
  v3 = (const char *)sub_1400014D8(v18);
  v4 = (const char *)sub_14000198C(v18);
  v5 = strstr(Str, v3);
  v6 = strstr(Str, v4);
  v7 = v6;
  if ( v5 != Str || !v6 )
    return sub_140001238(v18);
  v8 = -1i64;
  v9 = -1i64;
  do
    ++v9;
  while ( v3[v9] );
  v10 = &v5[v9];
  sub_140002900(v24, 0i64, 100i64);
  v11 = *v10;
  v12 = 0i64;
  if ( *v10 != 124 )
  {
    v13 = (char *)(v24 - v10);
    while ( v11 )
    {
      v10[(_QWORD)v13] = v11;
      ++v12;
      ++v10;
      if ( v12 < 0x63 )
      {
        v11 = *v10;
        if ( *v10 != 124 )
          continue;
      }
      if ( v12 >= 0x64 )
        _report_rangecheckfailure();
      break;
    }
  }
  v24[v12] = 0;
  sub_140002900(v25, 0i64, 100i64);
  do
    ++v8;
  while ( v4[v8] );
  v14 = &v7[v8];
  do
  {
    v15 = *v14;
    v14[v25 - &v7[v8]] = *v14;
    ++v14;
  }
  while ( v15 );
  v16 = sub_140001C20(v14);
  if ( strcmp(v24, (const char *)sub_1400015D8(v18)) || sub_140001FF8(v25) != v16 )
    return sub_140001398(v18);
  v19[0] = 1186659344;
  v19[1] = -1416519034;
  v19[2] = 107168791;
  v19[3] = 849122954;
  v19[4] = -1723421948;
  v19[5] = 2019559882;
  v19[6] = 1122034956;
  v19[7] = 1561138470;
  v19[8] = 1270755843;
  v19[9] = -609395383;
  v20 = 12277;
  v21 = 14;
  v22 = 0i64;
  sub_140002030((unsigned int)v19, 43, (unsigned int)v24, (unsigned int)&v22, (__int64)v23);
  v17 = (const CHAR *)sub_1400010F8(v18);
  DbgPrint(v17);
  return v22;
}
```
Takeaways:
1. Does string validation, most likely checking the "launch codes" supplied via the IOCTL payload. 
2. The form of the code should be v3XXXv4YYY
3. XXX has to match the return value of `sub_1400015D8()`
4. YYY has to match the return value of `sub_140001C20()`
5. `v22` or `v17` must be the flag. `v22` most likely, as the XXX value is used in that function (`sub_140002030`).

## Choosing a method
There are now 3 approaches/techniques to take as I see it.
1. Reverse or emulate the XXX launch code (`sub_1400015D8()`) and `sub_140002030` flag decryption function.
- Asking LLM to translate IDA pseudo code to C++, works a lot better than Python. An almost perfect result is in [passwordPrint.cpp](./passwordPrint.cpp) and [flagPrint.cpp](./flagPrint.cpp)  
This is the fastest method.
2. Debug and hotpatch(change memory) values or use them in client python script. Overwrite fail JMPs
3. Patch the JMPs leading to failure and point to the decrypted password - `sub_1400015D8()` instead of the XXX client input. Hard.

### Method 2: Debug and Python client
We now go back to WinDbg and the initial road that i took to solve the challenge. Not as efficient, and very ~~funny and educational~~ frustrating (the setup part).

In windbg, we want to break at:
1. 1337 check: `140001D64                 jnz     short loc_140001D72`  
``bp fffff805`69191d64``
2. v3 value: `1400021B3                 mov     rsi, rax` da @rax  
``bp fffff805`691921b3``
3. v4 value: `1400021C1                 mov     r15, rax` da @rax  
``bp fffff805`691921c1``
4. YYY value: `140002283                 mov     rbx, rax` r rax  
``bp fffff805`69192283``
5. XXX value: `14000228B                 lea     rcx, [rbp+80h+v24Password]` da @rax  
``bp fffff805`6919228b``
6. Ignore fail JMP modify EFLAGS: `1400022BB                 jnz     loc_140002361` r @efl = (@efl | 0x40)     
``bp fffff805`691922bb``
7. v22 Flag value: `14000235F                 jmp     short loc_140002377` da @rax
``bp fffff805`6919235f``

First load the driver with [My nifty bat script](./aStartMassDriver.bat)  
Then in WinDbg, get the driver info. Calculate the desired address you want to break on based on the base address of the MassDriver module. In IDA, the "base" address is 140000000, but IDA can easily rebase to 0 or the base address the driver was loaded at: `Edit->Segments->Rebase program...`

Useful WinDbg commands:
```
lmDvm MassDriver (Driver info and base address)
bp fffff805`69191d64 (breakpoint at MassDriver+0x1d64 / 140001D64)
g (continue execution)
bl (breakpoint list)
bc 0 (clear breakpoint 0)
r (show registers etc.)
da @rax (display ascii of what rax points to)
p (single step)
u @rip L5 (see next 5 instructions)
r rip = fffff801`5db62292 (set next instruction / skip to this instruction)
```

Output from WinDbg:
```
g
da @rax
ffffd505`42928db0  "PASSWORD:"
g
da @rax
ffffd505`45aecd10  "|ENGINE_BOOT_TIME:"
g
r rax
rax=00000000000000aa
g
da @rax
ffffd505`42928c50  "ENGINE_1337_GO"
g
r efl
efl=00040293
r @efl = (@efl | 0x40)
r efl
efl=000402d7
g
da @rax
ffffd505`46554d50  "TDCNET{MassDriver_20kmps_LunarLa"
ffffd505`46554d70  "unch_5kG}"
g
```

[Python client](./sol.py) output - when patching / ignoring the fail jump at +22BB:
```
[+] Opened handle to MassDriver.
[+] Device responded:
b'TDCNET{MassDriver_20kmps_LunarLaunch_5kG}'
TDCNET{MassDriver_20kmps_LunarLaunch_5kG}
Press any key to continue . . .
```
The client almost gets everything right. Except the YYY value. Which we now know is the ENGINE_BOOT_TIME.  
This value is apparently `Milli Seconds Since Boot * KeQueryTimeIncrement() / 10000000`. This is hard to estimate/simulate through the python client and I believe some bruteforcing would also be needed to get the value right. As if that wasn't enough, the client input value is scrambled before the comparison... so this is where I stop the reversing ;)

### Method 3: Binary patching 🙌
Exercising binary patching can quicky become ineffective, especially in a CTF context, but I want to demonstrate that it also can be a tactic, if the decryption function is too hard to reverse, or if you somehow don't have access to a debugger, which could be the case for this challenge, where it is hard to set up VM and remote debugging from scratch. Kernel patching is probably the worst kind of patching for beginners, because errors will result in blue-screens, rather than a program crash... I will do a few rounds of patching so the solution script will work eg. without password. In theory it would be possible to patch the program to not need any interaction at all and just print the flag to DebugPrint().

IDA only has a limited support for patching in assembly I.E. MOV ops are not supported... so for more advanced patching than just NOPs, I like to use [The Online x86 / x64 Assembler and Disassembler](https://defuse.ca/online-x86-assembler.htm#disassembly) (remember to put architecture to x64). Then after identifying the source and the target for patching, we do `Edit->Patch program->Assemble/Change byte...` after the patch is applied, choose `Apply patches to input file...` You will want to copy the "original file" which is now patched, call it MassDriver.sys so windows runs this file, and not the IDA file, since it may lock up the file for further patching and a restart will then be needed...  
Another tip: If you want to revert a patch, it is NOT engough to delete/Ctrl-Z it in IDA (int the patches view Ctrl+Alt+P), you must go to `patches to input file...` and check the box `Restore original bytes` BEFORE reverting them in IDA, otherwise IDA just forgets about the "dangling" patch next time it applies patches!

We will start from the bottom, since we already have everyting needed except the `ENGINE_BOOT_TIME` so we will patch the jump condition after the boot time comparison:
```
.text:00000001400022B3                 call    sub_140001FF8
.text:00000001400022B8                 cmp     rax, rbx
.text:00000001400022BB  jnz     loc_140002361
```
to this:
```
.text:00000001400022B3                 call    sub_140001FF8
.text:00000001400022B8                                 nop (x9)
```
Now the python client works completely without debugging ✨

Next up is the password. We don't need to know what value it has, we just want to supply it to the decryption function, the easiest must be to put rax (return val from password funciton) into r8 (the register that is expected by the flag decryption function to hold the password):
```
.text:0000000140002286                 call    PASSWORDsub_1400015D8
.text:000000014000228B                 lea     rcx, [rbp+80h+v24PasswordInput]
...
.text:00000001400022D8                 lea     r8, [rbp+80h+v24PasswordInput] (loads user input password)
```
```
.text:0000000140002286                 call    PASSWORDsub_1400015D8
.text:000000014000228B                 mov     r8, rax (49 89 c0) (load decrypted password)
nop (x51)
...
.text:00000001400022D8                 nop (x4) (don't load password input)
```
This patch will make the IDA decompilation look like this after pressing F5(to update the decompilation). As you can see, the decrypted password is supplied directly to the flag decryption function. After this patch, we can supply any password to the driver and it will return the flag.
```c
  YYYsub_140001C20();
  v16 = (char *)PASSWORDsub_1400015D8();
  v18[0] = 0x46BAFC10;
  v18[1] = 0xAB91A286;
  v18[2] = 0x6634417;
  v18[3] = 0x329C968A;
  v18[4] = 0x9946AB04;
  v18[5] = 0x786009CA;
  v18[6] = 0x42E0E50C;
  v18[7] = 0x5D0D1526;
  v18[8] = 0x4BBE3203;
  v18[9] = 0xDBAD5D49;
  v19 = 12277;
  v20 = 14;
  v22flag = 0i64;
  DEC_FLAGsub_140002030((__int64)v18, 0x2Bui64, v16, &v22flag, (unsigned __int64 *)v22);
```
Next we need to skip the check for the existence and correctness of the `PASSWORD:` and `|ENGINE_BOOT_TIME` field names. We simply jmp directly the the path that we patched:
- rel32 is the 4-byte signed offset from the address after the jmp instruction.

- You’re jumping from 0x14000219D to 0x140002286, so rel32 = 0xE4.

Patch bytes:  
`.text:000000014000219D 75 0A E8 F8 F8 → E9 E4 00 00 00`
Which will make the whole function look like this:
```c
  PASSWORD_INPUTv13 = PASSWORDsub_1400015D8();
  EXTRA_KEYSv16[0] = 1186659344;
  EXTRA_KEYSv16[1] = -1416519034;
  EXTRA_KEYSv16[2] = 107168791;
  EXTRA_KEYSv16[3] = 849122954;
  EXTRA_KEYSv16[4] = -1723421948;
  EXTRA_KEYSv16[5] = 2019559882;
  EXTRA_KEYSv16[6] = 1122034956;
  EXTRA_KEYSv16[7] = 1561138470;
  EXTRA_KEYSv16[8] = 1270755843;
  EXTRA_KEYSv16[9] = -609395383;
  v6 = 12277;
  v7 = 14;
  v22FLAG_DEC = 0i64;
  FLAG_DECRYPTIONsub_140002030((int)EXTRA_KEYSv16, 43, PASSWORD_INPUTv13, (int)&v22FLAG_DEC, (__int64)v9);
  v2 = (const CHAR *)SUCCESSsub_1400010F8(v4);
  DbgPrint(v2);
  return v22FLAG_DEC;
```
Now the driver returns the flag, as long as the control code is 0x13372000. This is an even simpler patch, so I will leave that one for you.  
Thanks for reading all the way to here! That means alot, I hope you enjoyed my writeup. Thanks to mad31k for a fine rev chall and to TDC NET for hosting this annual event!