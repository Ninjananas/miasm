#-*- coding:utf-8 -*-                                                                                                  

from builtins import range

import logging
from pyparsing import *
from miasm.expression.expression import *
from miasm.core.cpu import *
from collections import defaultdict
from miasm.core.bin_stream import bin_stream
import miasm.arch.wasm.regs as regs_module
from miasm.arch.wasm.regs import *
from miasm.core.asm_ast import AstInt, AstId, AstMem, AstOp
from miasm.loader.wasm_utils import encode_LEB128
from builtins import range
import struct

log = logging.getLogger("wasmdis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)

LPAR = Suppress('(')
RPAR = Suppress(')')
RESULT = Suppress('result')
EQUAL = Suppress('=')
OFFSET = Suppress('offset')
ALIGN = Suppress('align')

# (non-empty) block type parser
valtypes_str = ['f64', 'f32', 'i64', 'i32']
valtypes_expr = [ExprId(i, 8) for i in valtypes_str]
def valtype_str2expr(tokens):
    assert len(tokens) == 1 and len(tokens[0]) == 1 # In Wasm v1, a block can return at most one value
    i = valtypes_str.index(tokens[0][0])
    return AstId(valtypes_expr[i])

blocktype_val = Group(LPAR + RESULT + literal_list(valtypes_str) + RPAR).setParseAction(valtype_str2expr)

# Memargs
basic_deref = lambda x: x[0][0]
offset_parser = Optional(Group(OFFSET + EQUAL + base_expr), default=0).setParseAction(basic_deref)

def align_parser(default_value):
    return Optional(Group(ALIGN + EQUAL + base_expr), default=default_value).setParseAction(basic_deref)

# Floats
frac = Word(nums).setParseAction()

#print("======================")
#print(nums)
#print(aplhas)

#float_parser = Or()

class additional_info(object):

    def __init__(self):
        self.except_on_instr = False


class instruction_wasm(instruction):
    __slots__ = []
    delayslot = 0

    @property
    def has_memarg(self):
        try:
            opcode = struct.unpack('B', self.b[0])[0]
            return (0x27 < opcode) and (opcode < 0x3F)
        except TypeError:
            return self.name in [
                'i32.load',
                'i64.load',
                'f32.load',
                'f64.load',
                'i32.load8_s',
                'i32.load8_u',
                'i32.load16_s',
                'i32.load16_u',
                'i64.load8_s',
                'i64.load8_u',
                'i64.load16_s',
                'i64.load16_u',
                'i64.load32_s',
                'i64.load32_u', 
                'i32.store',
                'i64.store',
                'f32.store',
                'f64.store',
                'i32.store8',
                'i32.store16',
                'i64.store8',
                'i64.store16',
                'i64.store32',
            ]

    def to_string(self, loc_db=None):
        o = "%-10s " % self.name
        args = []
        for i, arg in enumerate(self.args):
            if not isinstance(arg, m2_expr.Expr):
                raise ValueError('zarb arg type')
            x = self.arg2str(arg, i, loc_db)
            args.append(x)
        if self.has_memarg:
            o += self.gen_memarg(args)
        else:
            o += self.gen_args(args)
        return o

    def gen_args(self, args):
        return ' '.join([str(x) for x in args])

    def gen_memarg(self, args):
        assert len(args) == 2
        return 'offset={} align={}'.format(str(args[0]), str(args[1]))

    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        if isinstance(expr, ExprInt): # Only valid for standard integers
            o = str(expr)
        elif isinstance(expr, ExprId):
            o = "(result {})".format(expr.name) #
        else:
            fds
        return o
        # if isinstance(expr, ExprId):
        #     o = str(expr)
        # elif isinstance(expr, ExprMem):
        #     if expr.ptr.is_int() or expr.ptr.is_id():
        #         o = "[%s]" % expr.ptr
        #     else:
        #         fds
        # elif expr.is_loc():
        #     if loc_db is not None:
        #         return loc_db.pretty_str(expr.loc_key)
        #     else:
        #        return str(expr)
            #     else:
            #         o = "0x0(%s)" % expr.ptr
            # elif isinstance(expr.ptr, ExprOp):
            #     o = "%s(%s)" % (expr.ptr.args[1], expr.ptr.args[0])

        # elif expr.is_loc():
        #     if loc_db is not None:
        #         return loc_db.pretty_str(expr.loc_key)
        #     else:
        #         return str(expr)
        # elif isinstance(expr, ExprOp) and expr.op == "autoinc":
        #     o = "@%s+" % str(expr.args[0])
        # elif isinstance(expr, ExprMem):
        #     if isinstance(expr.ptr, ExprId):
        #         if index == 0:
        #             o = "@%s" % expr.ptr
        #         else:
        #             o = "0x0(%s)" % expr.ptr
        #     elif isinstance(expr.ptr, ExprInt):
        #         o = "@%s" % expr.ptr
        #     elif isinstance(expr.ptr, ExprOp):
        #         o = "%s(%s)" % (expr.ptr.args[1], expr.ptr.args[0])
        # else:
        #     raise NotImplementedError('unknown instance expr = %s' % type(expr))
        # return o

    @property
    def is_structure(self):
        return self.name in ['loop', 'block', 'end', 'if', 'else']

    def dstflow(self):
        return self.name in ['br', 'br_if', 'br_table']

    def dstflow2label(self, loc_db):
        fds
        expr = self.args[1]
        if not isinstance(expr, ExprInt):
            return

        addr = int(expr)
        loc_key = loc_db.get_or_create_offset_location(addr)
        self.args[1] = ExprLoc(loc_key, expr.size)

    def breakflow(self):
        return self.name in ['br', 'br_if', 'br_table', 'if', 'else', 'call'] # call_indirect ?

    def splitflow(self):
        return self.name in ['br_if', 'if', 'call'] # call_indirect ?

    def setdstflow(self, a):
        fds

    def is_subcall(self):
        return self.name in ['call'] # call_indirect ?

    def getdstflow(self, loc_db):
        if self.name in ['br', 'br_if']:
            return self.args[0]
        fds

    def get_symbol_size(self, symbol, loc_db):
        fds

    def fixDstOffset(self):
        e = self.args[1]
        if not isinstance(e, ExprInt):
            log.debug('dyn dst %r', e)
            return
        off = int(e)
        if off % 2:
            raise ValueError('strange offset! %r' % off)
        self.args[1] = ExprInt(off, 16)

    def get_info(self, c):
        pass

    def __str__(self):
        o = super(instruction_wasm, self).__str__()
        return o

    def get_args_expr(self):
        args = []
        for a in self.args:
            args.append(a)
        return args

class mn_wasm(cls_mn):
    name = "wasm"
    regs = regs_module
    all_mn = []
    bintree = {}
    num = 0
    delayslot = 0
    pc = {None: PC}
    sp = {None: SP}
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    instruction = instruction_wasm
    # max_instruction_len = 50 #TODO#

    @classmethod
    def getpc(cls, attrib):
        return PC

    @classmethod
    def getsp(cls, attrib):
        return SP

    @classmethod
    def check_mnemo(cls, fields):
        pass
        #l = sum([x.l for x in fields])
        #assert l == 16, "len %r" % l

    # @classmethod
    # def getbits(cls, bs, attrib, start, n):
    #     if not n:
    #         return 0
    #     o = 0
    #     if n > bs.getlen() * 8:
    #         raise ValueError('not enough bits %r %r' % (n, len(bs.bin) * 8))
    #     while n:
    #         i = start // 8
    #         c = cls.getbytes(bs, i)
    #         if not c:
    #             raise IOError
    #         c = ord(c)
    #         r = 8 - start % 8
    #         c &= (1 << r) - 1
    #         l = min(r, n)
    #         c >>= (r - l)
    #         o <<= l
    #         o |= c
    #         n -= l
    #         start += l
    #     return o

    # @classmethod
    # def getbytes(cls, bs, offset, l=1):
    #     out = b""
    #     for _ in range(l):
    #         n_offset = (offset & ~1) + 1 - offset % 2
    #         out += bs.getbytes(n_offset, 1)
    #         offset += 1
    #     return out

    # def decoded2bytes(self, result):
    #     tmp = super(mn_wasm, self).decoded2bytes(result)
    #     out = []
    #     for x in tmp:
    #         o = b""
    #         while x:
    #             o += x[:2][::-1]
    #             x = x[2:]
    #         out.append(o)
    #     return out

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    def additional_info(self):
        info = additional_info()
        return info

    @classmethod
    def getmn(cls, name):
        return name

    def reset_class(self):
        super(mn_wasm, self).reset_class()

    def getnextflow(self, loc_db):
        raise NotImplementedError('not fully functional')



#########################################################
#########################################################

def addop(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_wasm,), dct)


class wasm_arg(m_arg):
    def asm_ast_to_expr(self, arg, loc_db):
        if isinstance(arg, AstInt):
            if hasattr(self, '_int_len'): # arg is LEB_128-encoded
                res = ExprInt(arg.value, self._int_len)
                if hasattr(arg, '_additional_info'): #TODO# retirer ?
                    res._additional_info = arg._additional_info
                return res
            fds
        if isinstance(arg, AstId):
            if isinstance(arg.name, ExprId):
                return arg.name
            fds
        fds
        if isinstance(arg, AstMem):
            if isinstance(arg.ptr, AstId) and isinstance(arg.ptr.name, str):
                return None
            ptr = self.asm_ast_to_expr(arg.ptr, loc_db)
            if ptr is None:
                return None
            return ExprMem(ptr, arg.size)
        fds
        if isinstance(arg, AstOp):
            args = [self.asm_ast_to_expr(tmp, loc_db) for tmp in arg.args]
            if None in args:
                return None
            return ExprOp(arg.op, *args)
        return None

mask_all = lambda x: (1 << x) - 1
mask_msb = lambda x: 1 << (x - 1)

def sxt(i, cur_l, dst_l):
    '''
    Sign extends the integer @i (encoded on @cur_l bits)
    to an int of @dst_l bits
    '''
    if cur_l < dst_l and i & mask_msb(cur_l) != 0:
        i |= mask_all(dst_l) ^ mask_all(cur_l)
    return i

def sct(i, cur_l):
    '''
    "Sign contracts" the @cur_l-bits integer @i as much as possible:
    - removes the MSBs while they are all the same
    - sign extends to the lowest 7-bit multiple greater than the result
    - returns a list of 7-bits inegers to encode
    '''
    n = cur_l
    msb_zero = True if i & mask_msb(n) == 0 else False
    res = i & mask_all(7)
    while n > 7:
        n -= 1
        if msb_zero ^ (i & mask_msb(n) == 0):
            n += 2
            res = i & mask_all(n)
            break
    res_array = []
    while n > 0:
        res_array.append(res & mask_all(7))
        res >>= 7
        n -= 7
    return res_array

class imm_7_noarg(imm_noarg):
    parser = base_expr

    def decode(self, v):
        self.expr = ExprInt(v, 7)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        self.value = int(self.expr)
        return True

class imm_7_arg(imm_7_noarg, wasm_arg):
    '''Last link (tail) of a LEB128 uninterpreted integer'''
    parser = base_expr

    def decode(self, v):
        val = 0
        n_bits = 0
        
        # Get previous bytes of the LEB128 integer
        for f in self.parent.fields_order:
            if f.cls is not None and f.cls[0] == imm_7_noarg:
                val += int(f.expr) * (1 << n_bits)
                n_bits += 7

        # Add current byte)
        val += v * (1 << n_bits)
        n_bits += 7

        # Sign extend and mask
        val = sxt(val, n_bits, self._int_len) | ((1<self._int_len) - 1)
        self.expr = ExprInt(val, self._int_len)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False

        # Value to encode in LEB_128
        LEB128_bytes = sct(int(self.expr), self._int_len)

        imm_noarg = [f for f in self.parent.fields_order
                     if f.cls is not None
                     and f.cls[0] == imm_7_noarg]

        # Check that the correct version of the instruction is used
        if len(imm_noarg) != len(LEB128_bytes) - 1:
            return False

        # Inject values
        for i in range(len(imm_noarg)):
            imm_noarg[i].expr = ExprInt(LEB128_bytes[i], 7)

        self.value = LEB128_bytes[-1]
        return True

class imm_7_arg_32(imm_7_arg):
    _int_len = 32

class imm_7_arg_64(imm_7_arg):
    _int_len = 64

class imm_7_arg_offset(imm_7_arg):
    _int_len = 32
    parser = offset_parser

class imm_7_arg_align_1(imm_7_arg):
    _int_len = 32
    parser = align_parser(1)

class imm_7_arg_align_2(imm_7_arg):
    _int_len = 32
    parser = align_parser(2)

class imm_7_arg_align_4(imm_7_arg):
    _int_len = 32
    parser = align_parser(4)

class imm_7_arg_align_8(imm_7_arg):
    _int_len = 32
    parser = align_parser(8)

VALTYPES = [
    (0x7F,'i32'),
    (0x7E,'i64'),
    (0x7D,'f32'),
    (0x7C,'f64'),
]

class imm_f32(wasm_arg):
    parser = base_expr

    def decode(self, v):
        pass

    def encode(self, v):
        pass

class block_result_no_empty(imm_noarg):
    parser = blocktype_val

    def decode(self, v):
        for val, name in VALTYPES:
            if val == v:
                self.expr = ExprId(name, 8)
                return True
        return False

    def encode(self):
        if not self.expr.is_id():
            return False
        for i, v in VALTYPES:
            if v == self.expr.name:
                self.value = i
                return True
        fds
        return False

single_byte_name = bs_name(l=8, name={
    'unreachable'         : 0x00,
    'nop'                 : 0x01,
    'else'                : 0x05,
    'end'                 : 0x0B,
    'return'              : 0x0F,
    'drop'                : 0x1A,
    'select'              : 0x1B,
    'i32.eqz'             : 0x45,
    'i32.eq'              : 0x46,
    'i32.ne'              : 0x47,
    'i32.lt_s'            : 0x48,
    'i32.lt_u'            : 0x49,
    'i32.gt_s'            : 0x4A,
    'i32.gt_u'            : 0x4B,
    'i32.le_s'            : 0x4C,
    'i32.le_u'            : 0x4D,
    'i32.ge_s'            : 0x4E,
    'i32.ge_u'            : 0x4F,
    'i64.eqz'             : 0x50,
    'i64.eq'              : 0x51,
    'i64.ne'              : 0x52,
    'i64.lt_s'            : 0x53,
    'i64.lt_u'            : 0x54,
    'i64.gt_s'            : 0x55,
    'i64.gt_u'            : 0x56,
    'i64.le_s'            : 0x57,
    'i64.le_u'            : 0x58,
    'i64.ge_s'            : 0x59,
    'i64.ge_u'            : 0x5A,
    'f32.eq'              : 0x5B,
    'f32.ne'              : 0x5C,
    'f32.lt'              : 0x5D,
    'f32.gt'              : 0x5E,
    'f32.le'              : 0x5F,
    'f32.ge'              : 0x60,
    'f64.eq'              : 0x61,
    'f64.ne'              : 0x62,
    'f64.lt'              : 0x63,
    'f64.gt'              : 0x64,
    'f64.le'              : 0x65,
    'f64.ge'              : 0x66,
    'i32.clz'             : 0x67,
    'i32.ctz'             : 0x68,
    'i32.popcnt'          : 0x69,
    'i32.add'             : 0x6A,
    'i32.sub'             : 0x6B,
    'i32.mul'             : 0x6C,
    'i32.div_s'           : 0x6D,
    'i32.div_u'           : 0x6E,
    'i32.rem_s'           : 0x6F,
    'i32.rem_u'           : 0x70,
    'i32.and'             : 0x71,
    'i32.or'              : 0x72,
    'i32.xor'             : 0x73,
    'i32.shl'             : 0x74,
    'i32.shr_s'           : 0x75,
    'i32.shr_u'           : 0x76,
    'i32.rotl'            : 0x77,
    'i32.rotr'            : 0x78,
    'i64.clz'             : 0x79,
    'i64.ctz'             : 0x7A,
    'i64.popcnt'          : 0x7B,
    'i64.add'             : 0x7C,
    'i64.sub'             : 0x7D,
    'i64.mul'             : 0x7E,
    'i64.div_s'           : 0x7F,
    'i64.div_u'           : 0x80,
    'i64.rem_s'           : 0x81,
    'i64.rem_u'           : 0x82,
    'i64.and'             : 0x83,
    'i64.or'              : 0x84,
    'i64.xor'             : 0x85,
    'i64.shl'             : 0x86,
    'i64.shr_s'           : 0x87,
    'i64.shr_u'           : 0x88,
    'i64.rotl'            : 0x89,
    'i64.rotr'            : 0x8A,
    'f32.abs'             : 0x8B,
    'f32.neg'             : 0x8C,
    'f32.ceil'            : 0x8D,
    'f32.floor'           : 0x8E,
    'f32.trunc'           : 0x8F,
    'f32.nearest'         : 0x90,
    'f32.sqrt'            : 0x91,
    'f32.add'             : 0x92,
    'f32.sub'             : 0x93,
    'f32.mul'             : 0x94,
    'f32.div'             : 0x95,
    'f32.min'             : 0x96,
    'f32.max'             : 0x97,
    'f32.copysign'        : 0x98,
    'f64.abs'             : 0x99,
    'f64.neg'             : 0x9A,
    'f64.ceil'            : 0x9B,
    'f64.floor'           : 0x9C,
    'f64.trunc'           : 0x9D,
    'f64.nearest'         : 0x9E,
    'f64.sqrt'            : 0x9F,
    'f64.add'             : 0xA0,
    'f64.sub'             : 0xA1,
    'f64.mul'             : 0xA2,
    'f64.div'             : 0xA3,
    'f64.min'             : 0xA4,
    'f64.max'             : 0xA5,
    'f64.copysign'        : 0xA6,
    'i32.wrap_i64'        : 0xA7,
    'i32.trunc_f32_s'     : 0xA8,
    'i32.trunc_f32_u'     : 0xA9,
    'i32.trunc_f64_s'     : 0xAA,
    'i32.trunc_f64_u'     : 0xAB,
    'i64.extend_i32_s'    : 0xAC,
    'i64.extend_i32_u'    : 0xAD,
    'i64.trunc_f32_s'     : 0xAE,
    'i64.trunc_f32_u'     : 0xAF,
    'i64.trunc_f64_s'     : 0xB0,
    'i64.trunc_f64_u'     : 0xB1,
    'f32.convert_i32_s'   : 0xB2,
    'f32.convert_i32_u'   : 0xB3,
    'f32.convert_i64_s'   : 0xB4,
    'f32.convert_i64_u'   : 0xB5,
    'f32.demote_f64'      : 0xB6,
    'f64.convert_i32_s'   : 0xB7,
    'f64.convert_i32_u'   : 0xB8,
    'f64.convert_i64_s'   : 0xB9,
    'f64.convert_i64_u'   : 0xBA,
    'f64.promote_f32'     : 0xBB,
    'i32.reinterpret_f32' : 0xBC,
    'i64.reinterpret_f64' : 0xBD,
    'f32.reinterpret_i32' : 0xBE,
    'f64.reinterpret_i64' : 0xBF,
})

addop('single_byte', [single_byte_name])

# Uninpterpreted integers
LEB128_byte = [bs('1'), bs(l=7, cls=(imm_7_noarg,))]
LEB128_tail_32 = [bs('0'), bs(l=7, cls=(imm_7_arg_32,))]
LEB128_tail_64 = [bs('0'), bs(l=7, cls=(imm_7_arg_64,))]
LEB128_tail_offset = [bs('0'), bs(l=7, cls=(imm_7_arg_offset,))]
LEB128_tail_align_1 = [bs('0'), bs(l=7, cls=(imm_7_arg_align_1,))]
LEB128_tail_align_2 = [bs('0'), bs(l=7, cls=(imm_7_arg_align_2,))]
LEB128_tail_align_4 = [bs('0'), bs(l=7, cls=(imm_7_arg_align_4,))]
LEB128_tail_align_8 = [bs('0'), bs(l=7, cls=(imm_7_arg_align_8,))]

i32_alternatives = [LEB128_byte*i + LEB128_tail_32 for i in range(5)]
i64_alternatives = [LEB128_byte*i + LEB128_tail_64 for i in range(10)]
offset_alternatives = [LEB128_byte*i + LEB128_tail_offset for i in range(5)]
align_alternatives_list = [
    [LEB128_byte*i + LEB128_tail_align_1 for i in range(5)],
    [LEB128_byte*i + LEB128_tail_align_2 for i in range(5)],
    [LEB128_byte*i + LEB128_tail_align_4 for i in range(5)],
    [LEB128_byte*i + LEB128_tail_align_8 for i in range(5)],
]

memarg_alternatives_1 = []
for off_alt in offset_alternatives:
    for ali_alt in align_alternatives_list[0]:
        memarg_alternatives_1.append(off_alt + ali_alt)

memarg_alternatives_2 = []
for off_alt in offset_alternatives:
    for ali_alt in align_alternatives_list[1]:
        memarg_alternatives_2.append(off_alt + ali_alt)

memarg_alternatives_4 = []
for off_alt in offset_alternatives:
    for ali_alt in align_alternatives_list[2]:
        memarg_alternatives_4.append(off_alt + ali_alt)

memarg_alternatives_8 = []
for off_alt in offset_alternatives:
    for ali_alt in align_alternatives_list[3]:
        memarg_alternatives_8.append(off_alt + ali_alt)

for i32 in i32_alternatives:
    addop('i32.const', [bs('01000001')] + i32)

for i64 in i64_alternatives:
    addop('i64.const', [bs('01000010')] + i64)

# Floating numbers
#TODO#
#addop('f32.const', [])

block_ret = bs(l=8, cls=(block_result_no_empty, wasm_arg))

# Structured instructions
#no return
addop('block', [bs('00000010'), bs('01000000')])
addop('loop',  [bs('00000011'), bs('01000000')])
addop('if',    [bs('00000100'), bs('01000000')])
#return
addop('block', [bs('00000010'), block_ret])
addop('loop',  [bs('00000011'), block_ret])
addop('if',    [bs('00000100'), block_ret])

# Branches
for idx in i32_alternatives:
    addop('br',    [bs('00001100')] + idx)
    addop('br_if', [bs('00001101')] + idx)
    #TODO# addop('br_table', [bs('00001110'), ??????])

# Calls
for idx in i32_alternatives:
    addop('call',          [bs('00010000')] + idx)
    addop('call_indirect', [bs('00010001')] + idx + [bs('00000000')])

# Variable instructions
var_instr_names = bs_name(l=8, name={
    'local.get' : 0x20,
    'local.set' : 0x21,
    'local.tee' : 0x22,
    'global.get': 0x23,
    'global.set': 0x24,
})
for idx in i32_alternatives:
    addop('var_instr', [var_instr_names] + idx)

# Memory instructions
#The 'align' field in most memory instructions has a default value
#This value depends on the instruction
mem_instr_default_1 = bs_name(l=8, name={
    'i32.load8_s': 0x2C,
    'i32.load8_u': 0x2D,
    'i64.load8_s': 0x30,
    'i64.load8_u': 0x31,
    'i32.store8' : 0x3A,
    'i64.store8' : 0x3C,
})
for alt in memarg_alternatives_1:
    addop('mem_instr_default_1', [mem_instr_default_1] + alt)

mem_instr_default_2 = bs_name(l=8, name={
    'i32.load16_s': 0x2E,
    'i32.load16_u': 0x2F,
    'i64.load16_s': 0x32,
    'i64.load16_u': 0x33,
    'i32.store16' : 0x3B,
    'i64.store16' : 0x3D,
})
for alt in memarg_alternatives_2:
    addop('mem_instr_default_2', [mem_instr_default_2] + alt)

mem_instr_default_4 = bs_name(l=8, name={
    'i32.load'    : 0x28,
    'f32.load'    : 0x2A,
    'i64.load32_s': 0x34,
    'i64.load32_u': 0x35,
    'i32.store'   : 0x36,
    'f32.store'   : 0x38,
    'i64.store32' : 0x3E,
})
for alt in memarg_alternatives_4:
    addop('mem_instr_default_4', [mem_instr_default_4] + alt)

mem_instr_default_8 = bs_name(l=8, name={
    'i64.load' : 0x29,
    'f64.load' : 0x2B,
    'i64.store': 0x37,
    'f64.store': 0x39,
})
for alt in memarg_alternatives_8:
    addop('mem_instr_default_8', [mem_instr_default_8] + alt)

addop('memory.size', [bs('0011111100000000')])
addop('memory.grow', [bs('0100000000000000')])
