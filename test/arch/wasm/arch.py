from __future__ import print_function

import time
from pdb import pm
from miasm.core.utils import decode_hex, encode_hex
from miasm.arch.wasm.arch import *
from miasm.core.locationdb import LocationDB

loc_db = LocationDB()

def h2i(s):
    return decode_hex(s.replace(' ', ''))


def u16swap(i):
    return struct.unpack('<H', struct.pack('>H', i))[0]

reg_tests_wasm = [
    ("xxxx    unreachable ",
     "00"),
    ("xxxx    nop        ",
     "01"),
    ("xxxx    i32.or     ",
     "72"),
    ("xxxx    i32.const  0xF5",
     "41f501"),
    ("xxxx    i32.const  0xFFFFFFFF",
     "417f"),
    ("xxxx    i64.const  0xFFFFFFFF",
     "42ffffffff0f"),
    ("xxxx    i32.const  0x7FFFFFFF",
     "41ffffffff07"),
    ("xxxx    i64.const  0x7FFFFFFF",
     "42ffffffff07"),
    ("xxxx    loop       (result i32)",
     "037f"),
    ("xxxx    block      ",
     "0240"),
    ("xxxx    br         0x0",
     "0c00"),
    ("xxxx    call       0x40",
     "10C000"),
]

ts = time.time()

for s, l in reg_tests_wasm:
    print("-" * 80)
    s = s[8:]
    b = h2i((l))
    print(repr(b))
    mn = mn_wasm.dis(b, None)
    print([str(x) for x in mn.args])
    print("'{}'".format(s))
    print("'{}'".format(mn))
    assert(str(mn) == s)
    l = mn_wasm.fromstring(s, loc_db, None)
    assert(str(l) == s)
    a = mn_wasm.asm(l)
    print([x for x in a])
    print(repr(b))
    assert(b in a)
