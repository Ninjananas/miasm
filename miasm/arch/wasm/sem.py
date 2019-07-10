#-*- coding:utf-8 -*-

from miasm.expression.expression import *
from miasm.arch.wasm.regs import *
from miasm.arch.wasm.arch import mn_wasm
from miasm.ir.ir import IntermediateRepresentation


def nop(ir, instr):
    return [],[]

def const(ir, instr, arg):
    e = push(ir, arg, instr.name.split('.')[0])
    return e, []

def drop(ir, instr):
    return [pop(ir)[0]], []

VT_SIZE = {
    'i32': 32,
    'i64': 64,
    'f32': 32,
    'i64': 64,
}

VT_REPR = {
    'i32': 0,
    'i64': 1,
    'f32': 2,
    'i64': 3,
}

def push(ir, val, vt):
    '''
    Push a value @val of type @vt on the
    operand stack
    Returns a list of ExprAssign
    '''
    aff = ExprAssign(ExprMem(ir.sp, val.size), val)
    aff_t = ExprAssign(ExprMem(ExprOp('+', ir.sp, ExprInt(val.size, ir.sp.size)), 8), ExprInt(VT_REPR[vt], 8))
    return [aff, aff_t, ExprAssign(ir.sp, ExprOp('+', ir.sp, ExprInt(val.size + 8, ir.sp.size)))]

def pop(ir, vt=None):
    '''
    Pops a value from the operand stack.
    Returns a tuple (pp, val) where:
    - pp is an ExprAssign to make to move the sp
    - val is an ExprMem to get the poped value
    Both must be, in the end, in the same AssignBlock
    Note that if vt is None, val is None too
    '''
    vt_stack = ExprMem(ExprOp('+', ir.sp, ExprOp('-', ExprInt(8, ir.sp.size))), 8)
    if vt is None:
        size_to_pop = ExprCond(ExprOp('parity', vt_stack),
                               ExprInt(40, ir.sp.size),
                               ExprInt(72, ir.sp.size))
    else:
        is_64 = VT_REPR[vt] & 1
        size_to_pop = ExprInt(32 * (is_64 + 1))
    pp = ExprAssign(ir.sp, ExprOp('+', ir.sp, ExprOp('-', size_to_pop)))

    if vt is None:
        return pp, None

    if is_64 == 0:
        off, sz = 40, 32
    else:
        off, sz = 72, 64
    val = ExprMem(ExprOp('+', ir.sp, ExprOp('-', ExprInt(off, ir.sp.size))), sz)
    return pp, val

mnemo_func = {
    'i32.const' : const,
    'i64.const' : const,
    'f32.const' : const,
    'f64.const' : const,
    'nop'       : nop,
    'block'     : nop,
    'loop'      : nop,
    'else'      : nop,
    'end'       : nop,
    'drop'      : drop,
}

class ir_wasm(IntermediateRepresentation):

    def __init__(self, loc_db=None):
        IntermediateRepresentation.__init__(self, mn_wasm, None, loc_db)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 32)
        self.addrsize = 32

    def get_ir(self, instr):
        args = instr.args
        instr_ir, extra_ir = mnemo_func[instr.name](self, instr, *args)
        return instr_ir, extra_ir

    def get_next_loc_key(self, instr): #TODO#
        fds
