/**

ST Microelectronics STM8 microprocessor analysis plugin

*/

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "stm8_optable.h"

static int analyse (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {

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
