/* 
=============
egvm-disasm.c
=============

This is a prototype of a linear sweep disassembler for EGVM bytecode [1].
As a bonus it tries to detect SMC and recover proper JMPs statements.

Instruction set:

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

I tried to keep it somewhat consistent with x86. All other bytes are treated 
as data.

For additional information, please see my writeup [2].

[1] http://www.sensepost.com/blog/10067.html
[2] http://dyjakan.sigsegv.pl
*/

#include <stdio.h>
#include <stdlib.h>

/* Global variables are the best, right? */
unsigned char bytecode[256];
unsigned char IP, SP, LC, LF;
unsigned char header[] = {
  0x65, 0x67, 0x76, 0x6d, 0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

void loader(char *filename) {
   FILE *fd;
   int i;

   fd = fopen(filename, "r+b");
   if(!fd) {
      printf("[-] Error: Couldn't open file\n");
      exit(1);
   }
   fread(bytecode, 0x1, 256, fd);
   fclose(fd);

   for(i=0; i<16; i++)
      if(bytecode[i] != header[i]) {
         printf("[-] Error: Invalid header\n");
         exit(1);
      }

   IP = bytecode[16];
   SP = bytecode[17];
   LC = bytecode[18];
   LF = 0x0;

   printf("IP (instruction pointer):\t%#x\n", IP);
   printf("SP (stack pointer):\t\t%#x\n", SP);
   printf("LC (loop counter):\t\t%#x\n\n", LC);
}

void disasm() {
   int i;
   
   printf("IP:\tSP:\tOPCODES:\tINSTRUCTIONS:\n");
   
   for(i=IP; i<256; i++) {
      
      printf("%#x\t%#x\t%.2x\t\t", i, SP, bytecode[i]);
      
      switch(bytecode[i]) {
         case 0x0:
            printf("BREAK\n");
            break;

         case 0x1:
            SP--;
            printf("POP\n");
            break;

         case 0x2:
            if(LC == 0) {
               LF = 0;
               printf("LOOP NOP\n");
            } else {
               LF = 1;
               printf("LOOP INIT\n");
            }
            break;

         /* This additional printing in opcodes 0x3, 0x5, and 0x6 is required 
            if we don't want to confuse second bytes of these instructions with
            other opcodes */

         case 0x3:
            if(LF == 1) {
               printf("JMP %#x\n", bytecode[++i]);
               printf("%#x\t%#x\t%.2x\t\tADDR\n", i, SP, bytecode[i]);
            } else {
               printf("JMP NOP\n");
               i++;
               printf("%#x\t%#x\t%.2x\t\tADDR\n", i, SP, bytecode[i]);
            }
            break;

         /* These IFs in 0x4, 0x5, and 0x6 are heurestics for detecting LC 
            change so we can have better disassembly of SMC */

         case 0x4:
            printf("MOV [%#x], ~[%#x]\n", SP, SP);
            if(SP == 0x12)
               LC = ~bytecode[SP];
            break;

         case 0x5:
            printf("MOV [%#x], [%#x]+%#x\n", SP, SP, bytecode[++i]);
            printf("%#x\t%#x\t%.2x\t\tARG\n", i, SP, bytecode[i]);
            if(SP == 0x12)
               LC = bytecode[SP]+bytecode[i];
            break;

         case 0x6:
            printf("MOV [%#x], [%#x]-%#x\n", SP, SP, bytecode[++i]);
            printf("%#x\t%#x\t%.2x\t\tARG\n", i, SP, bytecode[i]);
            if(SP == 0x12)
               LC = bytecode[SP]-bytecode[i];
            break;

         case 0x9:
            printf("DBG\n");
            break;

         case 0xB:
            printf("PRINT [%#x]\n", SP);
            break;

         default:
            printf("DB '%x'\n", bytecode[i]);
      }
   }
}

int main(int argc, char *argv[])
{
   if(argc != 2) {
      printf("[-] Usage: %s <bytecode_file>\n", argv[0]);
      exit(1);
   }

   loader(argv[1]);
   disasm();

   return 0;
}
