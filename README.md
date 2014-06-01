EGVM disassembler
=================

This is a prototype of a linear sweep disassembler for [EGVM](http://www.sensepost.com/blog/10067.html "") bytecode.

As a bonus it tries to detect SMC and recover proper JMPs statements.


Instruction set:
```
   IP = Instruction Pointer
   SP = Stack Pointer
   LC = Loop Counter
   LF = Loop Flag

   0x0 opcode = BREAK
   0x1 opcode = {SP--; POP}
   0x2 opcode = IF LC == 0 {LF=0; LOOP NOP} ELSE {LF=1; LOOP INIT}
   0x3 opcode = IF LF == 1 {JMP ADDR; IP++} ELSE {JMP NOP; IP++}
   0x4 opcode = MOV [SP], ~[SP]
   0x5 opcode = {MOV [SP], [SP]+ARG; IP++}
   0x6 opcode = {MOV [SP], [SP]-ARG; IP++}
   0xB opcode = PRINT [SP]
   0x9 opcode = DEBUG
```

I tried to keep it somewhat consistent with x86. All other bytes are treated as data.

For additional information, please see [my analysis](http://dyjakan.sigsegv.pl/2014/06/01/sensepost-reversing-challenge-analysis/ "").
