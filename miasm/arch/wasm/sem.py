#-*- coding:utf-8 -*-

from miasm.expression.expression import *
from miasm.arch.wasm.regs import *
from miasm.arch.wasm.arch import mn_wasm
from miasm.ir.ir import IntermediateRepresentation, IRBlock, AssignBlock


##### Utility functions #####

def i2expr(i, size):
    if isinstance(i, int):
        if i >= 0:
            return ExprInt(i, size)
        return ExprOp('-', ExprInt(-i, size))
    return i

##### Functions that make operations on stack #####
##### or depend on the stack implementation #####
'''
These functions return some IR that must be
executed to make some operations on the stack.
Only use these functions when you operate the stack,
so it's easier to change the way the stack work
The returned IR depends on the status of the stack,
use them carefully !
'''

# Sizes of types
VT_SIZE = {
    'i32': 32,
    'i64': 64,
    'f32': 32,
    'i64': 64,
}

# Representation of value types on stack
VT_REPR = {
    'i32': 0,
    'i64': 1,
    'f32': 2,
    'i64': 3,
}

def size_on_stack(vt):
   # Assumes vt is a correct calue type
    if vt[1:] == '64':
        return 9
    return 5

def overwrite_at(ir, ofs, val):
    '''
    Returns an ExprAssign that writes the value @val
    on the stack at sp+@ofs
    '''
    ofs = i2expr(ofs, ir.sp.size)
    return ExprAssign(ExprMem(ExprOp('+', ir.sp, ofs), val.size), val)

def get_at(ir, ofs, vt):
    '''
    Returns an Expr which holds the value contained
    on the stack at sp+@ofs
    '''
    ofs = i2expr(ofs, ir.sp.size)
    return ExprMem(ExprOp('+', ir.sp, ofs), VT_SIZE[vt])

def add_sp(ir, n_bytes):
    '''
    Returns an ExprAssign to add a shift to the SP
    '''
    shf = i2expr(n_bytes, ir.sp.size)
    return ExprAssign(ir.sp, ExprOp('+', ir.sp, shf))

def push(ir, val, vt, ofs=0):
    '''
    "Pushes" a value on the stack.
    Returns a list of ExprAssign that:
    - Moves the SP accordingly
    - Write the value on the stack
    The parameter @ofs enables to move the SP
    before pushing
    '''
    ofs = i2expr(ofs, ir.sp.size)
    shf = i2expr(-size_on_stack(vt), ir.sp.size)
    target = ExprOp('+', ofs, shf)
    mv_sp = add_sp(ir, target)
    w_val = overwrite_at(ir, ExprOp('+', ExprInt(1, ir.sp.size), target), val)
    w_vt = overwrite_at(ir, target, i2expr(VT_REPR[vt], 8))
    return [mv_sp, w_val, w_vt]

def get_last_value_size(ir):
    return ExprCond(ExprOp('&', ExprMem(ir.sp, 8), ExprInt(1, 8)),
                    ExprInt(9, ir.sp.size),
                    ExprInt(5, ir.sp.size))

def pop(ir, vt=None, n=1):
    '''
    "Pops" a value (or @n values) from the operand stack.
    If @vt is None, @n is ignored and only one value is poped
    Returns a tuple (shf, val) where:
    - shf is an Expr holding the value to add to the stack
    - ofs_vals is a list of Expr holding offsets to get the poped values
    Note that if @vt is None, val is None too
    '''
    if vt is None:
        return get_last_value_size(ir), None

    size_per_item = size_on_stack(vt)
    size_to_pop = ExprInt(size_per_item * n, ir.sp.size)

    is_64 = VT_REPR[vt] & 1 == 1
    ofs_vals = [i2expr(1 + (i*size_per_item), ir.sp.size) for i in range(n)]
    return i2expr(size_per_item * n, ir.sp.size), ofs_vals

##### Mnemonics functions #####

def nop(ir, instr):
    return [],[]

def const(ir, instr, arg):
    e = push(ir, arg, instr.name.split('.')[0])
    return e, []

def drop(ir, instr):
    a = pop(ir)[0]
    return [add_sp(ir, a)], []


## Operations on integers

IUNOPS = {
    'clz': lambda vals: fds,
    'ctz': lambda vals: fds,
    'popcnt': lambda vals: fds,
}

def iunop(ir, instr):
    '''
    Unary operation on integer:
    Consumes 1 operand on stack
    Produces 1 operand of same type
    '''
    vt, op = instr.name.split('.')
    # get operands
    _, ofs_vals = pop(ir, vt, 1)
    res = IUNOPS[op]([get_at(ir, ofs_vals[0], vt)])
    # Overwrite the value that has not been poped
    aff_res = overwrite_at(ir, ofs_vals[0], res)
    return [aff_res], []


IBINOPS = {
    'add': lambda vals: ExprOp('+', vals[0], vals[1]),
    'sub': lambda vals: ExprOp('+', vals[0], ExprOp('-', vals[1])),
    'mul': lambda vals: ExprOp('*', vals[0], vals[1]),
    'and': lambda vals: ExprOp('&', vals[0], vals[1]),
    'or': lambda vals: ExprOp('|', vals[0], vals[1]),
    'xor': lambda vals: ExprOp('^', vals[0], vals[1]),
    'shl': lambda vals: fds,
    'rotl': lambda vals: fds,
    'rotr': lambda vals: fds,
    'div_u': lambda vals: fds,
    'rem_u': lambda vals: fds,
    'shr_u': lambda vals: fds,
    'div_s': lambda vals: fds,
    'rem_s': lambda vals: fds,
    'shr_s': lambda vals: fds,
}

def ibinop(ir, instr):
    '''
    Binary operation on integer:
    Consumes 2 operands on stack
    Produces 1 operand of same type
    '''
    vt, op = instr.name.split('.')
    # get operands and make operation
    _, ofs_vals = pop(ir, vt, 2)
    res = IBINOPS[op]([get_at(ir, ofs, vt) for ofs in ofs_vals])
    aff_res = overwrite_at(ir, ofs_vals[1], res)
    
    # Move the stack
    mv_sp = add_sp(ir, size_on_stack(vt))
    return [mv_sp, aff_res], []


ITESTOPS = {
    'eqz': lambda vals: ExprCond(vals[0], ExprInt(0xaa, 32), ExprInt(0xbb, 32)),
}

def itestop(ir, instr):
    '''
    Test operation on integer:
    Consumes 1 operand on stack
    Produces 1 boolean (i32) operand
    '''
    vt, op = instr.name.split('.')
    # get operands
    pp, ofs_vals = pop(ir, vt, 1)
    res = ITESTOPS[op]([get_at(ir, ofs, vt) for ofs in ofs_vals])
    # Push result of operation on the previous value
    push_res = push(ir, res, 'i32', pp)

    return push_res, []

IRELOPS = {
    'eq': lambda: fds,
    'ne': lambda: fds,
    'lt_s': lambda: fds,
    'lt_u': lambda: fds,
    'gt_s': lambda: fds,
    'gt_u': lambda: fds,
    'le_s': lambda: fds,
    'le_u': lambda: fds,
    'ge_s': lambda: fds,
    'ge_u': lambda: fds,
}

def irelop(ir, instr):
    '''
    Comparison operation on integer:
    Consumes 2 operand on stack
    Produces 1 boolean (i32) operand
    '''
    vt, op = instr.name.split('.')
    # get operands
    pp, ofs_vals = pop(ir, vt, 2)
    res = ITESTOPS[op]([get_at(ir, ofs, vt) for ofs in ofs_vals])
    # Push result of operation on the previous value
    push_res = push(ir, res, 'i32', pp)

    return push_res, []



##### Mnemonics indexing #####

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
    'i32.add'   : ibinop,
    'i32.sub'   : ibinop,
    'i32.mul'   : ibinop,
    'i32.and'   : ibinop,
    'i32.or'    : ibinop,
    'i32.xor'   : ibinop,
    'i32.shl'   : ibinop,
    'i32.rotl'  : ibinop,
    'i32.rotr'  : ibinop,
    'i32.div_u' : ibinop,
    'i32.rem_u' : ibinop,
    'i32.shr_u' : ibinop,
    'i32.div_s' : ibinop,
    'i32.rem_s' : ibinop,
    'i32.shr_s' : ibinop,
    'i64.add'   : ibinop,
    'i64.sub'   : ibinop,
    'i64.mul'   : ibinop,
    'i64.and'   : ibinop,
    'i64.or'    : ibinop,
    'i64.xor'   : ibinop,
    'i64.shl'   : ibinop,
    'i64.rotl'  : ibinop,
    'i64.rotr'  : ibinop,
    'i64.div_u' : ibinop,
    'i64.rem_u' : ibinop,
    'i64.shr_u' : ibinop,
    'i64.div_s' : ibinop,
    'i64.rem_s' : ibinop,
    'i64.shr_s' : ibinop,
    'i32.eqz'   : itestop,
    'i64.eqz'   : itestop,
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
