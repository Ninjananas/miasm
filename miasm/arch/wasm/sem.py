#-*- coding:utf-8 -*-

from miasm.expression.expression import *
#from miasm.arch.toy.regs import *
from miasm.arch.wasm.arch import mn_wasm
from miasm.ir.ir import IntermediateRepresentation

'''
def sub(ir, instr, d, s, t):
    e = []
    e.append(ExprAssign(d, s-t))
    return e, []

def add(ir, instr, d, s, t):
    e = []
    e.append(ExprAssign(d, s+t))
    return e, []

def jz(ir, instr, reg, addr):
    e = []
    loc_next_expr = ExprLoc(ir.get_next_loc_key(instr), 8)
    e.append(ExprAssign(ir.IRDst, ExprCond(ExprOp(TOK_EQUAL, reg, ExprInt(0, reg.size)), addr, loc_next_expr)))
    return e, []

def halt(ir, instr):
    return [ExprAssign(ir.IRDst, ExprId('END', 8))], []

mnemo_func = {
    'add' : add,
    'sub' : sub,
    'jz'  : jz,
    'halt': halt,
}

class ir_toy(IntermediateRepresentation):

    def __init__(self, loc_db=None):
        IntermediateRepresentation.__init__(self, mn_toy, None, loc_db)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 8)
        self.addrsize = 8

    def get_ir(self, instr):
        args = instr.args
        instr_ir, extra_ir = mnemo_func[instr.name](self, instr, *args)

        return instr_ir, extra_ir
'''

PUSH_STACK = {
    'i32': ExprAff(ExprMem(SP, )),
}

VT_SIZE = {
    'i32': 32,
    'i64': 64,
    'f32': 32,
    'i64': 64,
}

#TODO# push/pop : flottants ?
def push(ir, valtype, val):
    '''
    Push a value on the operand stack
    Returns a list of ExprAssign
    '''
    size = VT_SIZE[valtype]
    aff = ExprAssign(ExprMem(ir.sp, size), ExprInt(val, size))
    return [aff, ExprAssign(ir.sp, ExprOp('+', ir.sp, ExprInt(size, ir.sp.size)))]

def pop(ir, valtype):
    '''
    Pops a value from the operand stack
    '''
    size = VT_SIZE[valtype]
    
    return [ExprAssign(ir.sp, ExprOp('-', ir.sp, ExprInt(size, ir.sp.size)))]

mnemo_func = {
    
}

class ir_wasm(IntermediateRepresentation):

    def __init__(self, loc_db=None):
        IntermediateRepresentation.__init__(self, mn_wasm, None, loc_db)
        #self.pc = PC
        #self.sp = SP
        self.IRDst = ExprId('IRDst', 64)
        #self.addrsize = 64

    def get_ir(self, instr):
        args = instr.args
        instr_ir, extra_ir = mnemo_func[instr.name](self, instr, *args)
        return instr_ir, extra_ir

    def get_next_loc_key(self, instr): #TODO#
        loc_key = self.loc_db.get_or_create_offset_location(instr.offset + instr.l)
        return loc_key
