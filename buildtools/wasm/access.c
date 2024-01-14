
#include "capstone/capstone.h"

char* cs_get_mnemonic(cs_insn* insn)
{
    return insn->mnemonic;
}

char* cs_get_op_str(cs_insn* insn)
{
    return insn->op_str;
}
