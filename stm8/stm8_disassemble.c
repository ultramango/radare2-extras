/* STM8 disassembler based on naked_asm
   naked_asm: http://www.mikekohn.net/micro/naken_asm.php

  *  naken_asm assembler.
  *  Author: Michael Kohn
  *   Email: mike@mikekohn.net
  *     Web: http://www.mikekohn.net/
  * License: GPLv3
  *
  * Copyright 2010-2017 by Michael Kohn
  *
*/

#include <r_asm.h>
#include <r_lib.h>

#include "stm8_disassemble.h"
#include "stm8_optable.h"


#define READ_RAM(a) (*(b+a))
#define READ_RAM16(a) ( ((*(b+a))<<8)  | (*(b+a+1)) )
#define READ_RAM24(a) ( ((*(b+a))<<16) | ((*(b+a))<<8) | (*(b+a+1)) )


// Transform instruction enum to a string
static void get_instruction (char *instr, int instr_enum)
{
  int n;

  n = 0;
  while(table_stm8[n].instr != NULL)
  {
    if (table_stm8[n].instr_enum == instr_enum)
    {
      strcpy(instr, table_stm8[n].instr);
      break;
    }
    n++;
  }
}

// Add register text based on register enum
void add_reg(char *instr, int reg)
{
  int n;

  n = 0;
  while (table_stm8_regs[n].reg_enum != 0)
  {
    if (table_stm8_regs[n].reg_enum == reg)
    {
      strcat (instr, table_stm8_regs[n].reg);
      break;
    }
    n++;
  }
}

//int disasm_stm8(struct _memory *memory, uint32_t address, char *instr, int *cycles_min, int *cycles_max)
static int disassemble (RAsm *a, RAsmOp *op, const ut8 *b, int l) {
  ut8 opcode;
  ut8 prefix = 0; // Initially prefix is none, can be a special opcode, see PM0044
                  // Has to be 0 as this is the default matching value in big instruction table
  ut8 offset;
  char temp[128];
  char instr[128];
  int count = 1; // How many bytes processed in the stream
  int n;

  instr[0] = 0;

  // This is actually not used in radare (TODO: place as a comment in final output)
  int cycles_min = -1;
  int cycles_max = -1;

  // Handle special prefixes for instructions, see programmers manual, search for "PM0044"
  opcode = *b;
  if (opcode == 0x90 || opcode == 0x91 || opcode == 0x92 || opcode == 0x72)
  {
    prefix = opcode;
    opcode = *(b + count);
    count++;
  }

  // Find the curent opcode in STM8 opcode table
  n = 0;
  while(table_stm8_opcodes[n].instr_enum != STM8_NONE)
  {
    if (table_stm8_opcodes[n].prefix == prefix)
    {
      if (table_stm8_opcodes[n].opcode == opcode)
      {
        break;
      }

      // TODO: what type of instructions are these?
      if (prefix != 0 && (table_stm8_opcodes[n].opcode & 0xf0) == 0x10 &&
          table_stm8_opcodes[n].opcode == (opcode & 0xf1))
      {
        break;
      }

      // TODO: what type of instructions are these?
      if (prefix != 0 && (table_stm8_opcodes[n].opcode & 0xf0) == 0x00 &&
          table_stm8_opcodes[n].opcode == (opcode & 0xf1))
      {
        break;
      }
    }
    n++;
  }

  // If instruction can't be found...
  if (table_stm8_opcodes[n].instr_enum == STM8_NONE)
  {
    // TODO: this should be ".db 0x12"
    strcpy(instr, "???");
    op->size = count;
    return op->size;
  }

  cycles_min = table_stm8_opcodes[n].cycles_min;
  cycles_max = table_stm8_opcodes[n].cycles_max;

  // Get string representation of the opcode
  get_instruction(instr, table_stm8_opcodes[n].instr_enum);

  // If opcode accepts arguments - insert a space
  if (table_stm8_opcodes[n].type != OP_NONE)
  {
    strcat(instr, " ");
  }

  if (table_stm8_opcodes[n].dest != 0) // TODO: shouldn't this be OP_NONE?
  {
    // Add the destination register (string) to final output
    add_reg(instr, table_stm8_opcodes[n].dest);

    // If this is a two argument operation - put a comma
    if (table_stm8_opcodes[n].type != OP_NONE &&
        table_stm8_opcodes[n].type != OP_SINGLE_REGISTER)
    {
      strcat(instr, ", ");
    }
  }

  // What is the type of argument
  switch(table_stm8_opcodes[n].type)
  {
    case OP_NONE:
      break;

    case OP_NUMBER8:
      sprintf(temp, "#$%02x", READ_RAM(count));
      strcat(instr, temp);
      count++;
      break;

    case OP_NUMBER16:
      sprintf(temp, "#$%x", READ_RAM16(count));
      strcat(instr, temp);
      count += 2;
      break;

    case OP_ADDRESS8:
      sprintf(temp, "$%02x", READ_RAM(count));
      strcat(instr, temp);
      count++;
      break;

    case OP_ADDRESS16:
      sprintf(temp, "$%x", READ_RAM16(count));
      strcat(instr, temp);
      count += 2;
      break;

    case OP_ADDRESS24:
      sprintf(temp, "$%x", READ_RAM24(count));
      strcat(instr, temp);
      count += 3;
      break;

    case OP_INDEX_X:
      strcat(instr, "(X)");
      break;

    case OP_OFFSET8_INDEX_X:
      sprintf(temp, "($%02x,X)", READ_RAM(count));
      strcat(instr, temp);
      count++;
      break;

    case OP_OFFSET16_INDEX_X:
      sprintf(temp, "($%x,X)", READ_RAM16(count));
      strcat(instr, temp);
      count += 2;
      break;

    case OP_OFFSET24_INDEX_X:
      sprintf(temp, "($%x,X)", READ_RAM24(count));
      strcat(instr, temp);
      count += 3;
      break;

    case OP_INDEX_Y:
      strcat(instr, "(Y)");
      break;

    case OP_OFFSET8_INDEX_Y:
      sprintf(temp, "($%02x,Y)", READ_RAM(count));
      strcat(instr, temp);
      count++;
      break;

    case OP_OFFSET16_INDEX_Y:
      sprintf(temp, "($%x,Y)", READ_RAM16(count));
      strcat(instr, temp);
      count += 2;
      break;

    case OP_OFFSET24_INDEX_Y:
      sprintf(temp, "($%x,Y)", READ_RAM24(count));
      strcat(instr, temp);
      count += 3;
      break;

    case OP_OFFSET8_INDEX_SP:
      sprintf(temp, "($%02x,SP)", READ_RAM(count));
      strcat(instr, temp);
      count++;
      break;

    case OP_INDIRECT8:
      sprintf(temp, "[$%02x.w]", READ_RAM(count));
      strcat(instr, temp);
      count++;
      break;

    case OP_INDIRECT16:
      sprintf(temp, "[$%x.w]", READ_RAM16(count));
      strcat(instr, temp);
      count += 2;
      break;

    case OP_INDIRECT16_E:
      sprintf(temp, "[$%x.e]", READ_RAM16(count));
      strcat(instr, temp);
      count += 2;
      break;

    case OP_INDIRECT8_X:
      sprintf(temp, "([$%02x.w],X)", READ_RAM(count));
      strcat(instr, temp);
      count++;
      break;

    case OP_INDIRECT16_X:
      sprintf(temp, "([$%x.w],X)", READ_RAM16(count));
      strcat(instr, temp);
      count += 2;
      break;

    case OP_INDIRECT16_E_X:
      sprintf(temp, "([$%x.e],X)", READ_RAM16(count));
      strcat(instr, temp);
      count += 2;
      break;

    case OP_INDIRECT8_Y:
      sprintf(temp, "([$%02x.w],Y)", READ_RAM(count));
      strcat(instr, temp);
      count++;
      break;

    case OP_INDIRECT16_E_Y:
      sprintf(temp, "([$%x.e],Y)", READ_RAM16(count));
      strcat(instr, temp);
      count += 2;
      break;

    case OP_ADDRESS_BIT:
      sprintf(temp, "$%x, #%d", READ_RAM16(count), (opcode & 0x0e) >> 1);
      strcat(instr, temp);
      count += 2;
      break;

    case OP_ADDRESS_BIT_LOOP:
      offset = (int8_t)READ_RAM(count + 2);
      sprintf(temp, "$%x, #%d, $%x  (offset=%d)", READ_RAM16(count), (opcode & 0x0e) >> 1, (count + 3) + offset, offset);
      strcat(instr, temp);
      count += 3;
      break;

    case OP_RELATIVE:
      offset = (int8_t)READ_RAM(count);
      sprintf(temp, "$%x  (offset=%d)", (count + 1) + offset, offset);
      strcat(instr, temp);
      count++;
      break;

    case OP_SINGLE_REGISTER:
    case OP_TWO_REGISTERS:
      break;

    case OP_ADDRESS16_NUMBER8:
      sprintf(temp, "$%x, #$%02x", READ_RAM16(count + 1), READ_RAM(count));
      strcat(instr, temp);
      count += 3;
      break;

    case OP_ADDRESS8_ADDRESS8:
      sprintf(temp, "$%x, $%02x", READ_RAM(count + 1), READ_RAM(count));
      strcat(instr, temp);
      count += 2;
      break;

    case OP_ADDRESS16_ADDRESS16:
      sprintf(temp, "$%x, $%x", READ_RAM16(count + 2), READ_RAM16(count));
      strcat(instr, temp);
      count += 4;
      break;

    default:
      strcpy(instr, "???");
      break;
  }

  // What is this?
  if (table_stm8_opcodes[n].src != 0)
  {
    if (table_stm8_opcodes[n].type != OP_NONE &&
        table_stm8_opcodes[n].type != OP_TWO_REGISTERS)
    {
      strcat(instr, ",");
    }

    add_reg(instr, table_stm8_opcodes[n].src);
  }

  // Copy what we created to output buffer
  strcpy(op->buf_asm, instr);

  op->size = count;
  return op->size;
}

RAsmPlugin r_asm_plugin_stm8 = {
  .name = "stm8",
  .arch = "stm8",
  .license = "GPL3",
  .bits = 8,
  .desc = "STM8 disassembler",
  .disassemble = &disassemble,
};

#ifndef CORELIB
//RLibStruct radare_plugin = {
struct r_lib_struct_t radare_plugin = {
  .type = R_LIB_TYPE_ASM,
  .data = &r_asm_plugin_stm8,
};
#endif
