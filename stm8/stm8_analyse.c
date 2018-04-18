/**

ST Microelectronics STM8 microprocessor analysis plugin

Uses code from naken_asm: http://www.mikekohn.net/

*/

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "stm8_optable.h"

// typedef struct r_anal_op_t {
//         char *mnemonic; /* mnemonic */
//         ut64 addr;      /* address */
//         ut32 type;      /* type of opcode */
//         ut64 prefix;    /* type of opcode prefix (rep,lock,..) */
//         ut32 type2;     /* used by java */
//         int group;      /* is fpu, is privileged, mmx, etc */
//         int stackop;    /* operation on stack? */
//         int cond;       /* condition type */
//         int size;       /* size in bytes of opcode */
//         int nopcode;    /* number of bytes representing the opcode (not the arguments) TODO: find better name */
//         int cycles;     /* cpu-cycles taken by instruction */
//         int failcycles; /* conditional cpu-cycles */
//         int family;     /* family of opcode */
//         int id;         /* instruction id */
//         bool eob;       /* end of block (boolean) */
//         /* Run N instructions before executing the current one */
//         int delay;      /* delay N slots (mips, ..)*/
//         ut64 jump;      /* true jmp */
//         ut64 fail;      /* false jmp */
//         int direction;  /* 1 = read, 2 = write, 4 = exec, 8 = reference,  */
//         st64 ptr;       /* reference to memory */ /* XXX signed? */
//         ut64 val;       /* reference to value */ /* XXX signed? */
//         int ptrsize;    /* f.ex: zero extends for 8, 16 or 32 bits only */
//         st64 stackptr;  /* stack pointer */
//         int refptr;     /* if (0) ptr = "reference" else ptr = "load memory of refptr bytes" */
//         RAnalVar *var;  /* local var/arg used by this instruction */
//         RAnalValue *src[3];
//         RAnalValue *dst;
//         struct r_anal_op_t *next; // TODO deprecate
//         RStrBuf esil;
//         RStrBuf opex;
//         const char *reg; /* destination register */
//         const char *ireg; /* register used for indirect memory computation*/
//         int scale;
//         ut64 disp;
//         RAnalSwitchOp *switch_op;
//         RAnalHint hint;
// } RAnalOp;




// Based on https://github.com/radare/radare2/commit/64636e9505f9ca8b408958d3c01ac8e3ce254a9b
static int analyse (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
    // Preinit instructions
    memset (op, '\0', sizeof (RAnalOp));
    op->size = 0; // Size of the instruction
    op->addr = addr; // Address of the instruction
    op->type = R_ANAL_OP_TYPE_UNK; // Type of the instruction



    return op->size;
}


RAnalPlugin r_anal_plugin_stm8 = {
    .name = "stm8",
    .desc = "STM8 analysis plugin",
    .license = "GPL3",
    .arch = R_SYS_ARCH_NONE,
    .bits = 8,
    .init = NULL,
    .fini = NULL,
    .op = &analyse,
    .set_reg_profile = NULL,
    .fingerprint_bb = NULL,
    .fingerprint_fcn = NULL,
    .diff_bb = NULL,
    .diff_fcn = NULL,
    .diff_eval = NULL
};

#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ANAL,
    .data = &r_anal_plugin_stm8,
    .version = R2_VERSION
};
#endif
