#from builtins import range
from miasm.expression.expression import *
#from miasm.core.cpu import reg_info


PC = ExprId('PC', 32)
SP = ExprId('SP', 32)

# Block pointer
# A pointer on a parallel stack storing
# the encountered Wasm structures
BP = ExprId('BP', 32)

PC_init = ExprId("PC_init", 32)
SP_init = ExprId("SP_init", 32)
BP_init = ExprId("BP_init", 32)


regs_init = {
    PC: PC_init,
    SP: SP_init,
    BP: BP_init,
}
