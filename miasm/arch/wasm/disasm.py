from miasm.core.asmblock import disasmEngine, AsmBlock
from miasm.core.utils import Disasm_Exception
from miasm.arch.wasm.arch import mn_wasm
from miasm.core.asmblock import AsmConstraint, AsmCFG
from miasm.loader.wasm_init import is_imported
import copy
import logging

log_asmblock = logging.getLogger("asmblock")

def get_loc(loc_db, func_name, offset):
    return loc_db.get_or_create_name_location(func_name + '_{}'.format(offset))

class WasmStruct(object):
    '''
    Defines a Wasm structure (its start and its stop)
    The possible kinds of structures are:
    'func', 'loop', 'block', 'if'
    '''
    __slots__ = ['kind', 'start_key', 'end_key', 'after_else_key', 'func_name']

    def __init__(self, loc_db, kind, func_name, start_offset):
        self.func_name = func_name
        self.kind = kind
        self.start_key = get_loc(loc_db, func_name, start_offset)
        self.end_key = None
        self.after_else_key = None

    def set_end_off(self, loc_db, offset):
        if self.end_key is not None:
            raise Exception('Malformed code')
        self.end_key = get_loc(loc_db, self.func_name, offset)
        if self.kind == 'if' and self.after_else_key is None:
            self.after_else_key = self.end_key
        

    def set_else_off(self, loc_db, offset):
        if self.kind != 'if' or self.after_else_key is not None:
            raise Exception('Malformed code')
        # 1 is the length of the 'else' pseudo-instruction
        self.after_else_key = get_loc(loc_db, self.func_name, offset)

    @property
    def branch_key(self):
        if self.kind == 'loop':
            return self.start_key
        return self.end_key

class PendingBasicBlocks(object):
    '''
    Feed this object with offsets of structured instructions and basic blocks
    For this to work you must:
    - declare every structured instruction you
      ('loop', 'block', 'if', 'else', 'end')
    - declare function start with the dummy instruction name 'func'
    - declare every basic block you encounter
    - all these declaration must be made in order
    This object will store basic blocks and update them when needed.
    It updates basic blocks that end with:
    - branches ('br', 'br_if')
    - 'if' pseudo instruction
    - 'else' pseudo instruction
    by finding their true dstflow and adding the corresponding
    location to the block's bto.
    During disassembly, please declare structured
    instructions BEFORE adding a basic block
    '''
    __slots__ = ['_if_todo', '_br_todo', 'done', 'loc_db', '_structs', 'func_name']

    def __init__(self, loc_db, func_name):
        self.func_name = func_name
        self.loc_db = loc_db
        self._br_todo = []
        self._if_todo = []
        self.done = []
        self._structs = []

    def _add_done(self, block):
        self.done.append(block)
        block.fix_constraints()

    def structure_instr_at(self, kind, offset):
        if kind in ['func', 'loop', 'block', 'if']:
            self._structs.append(WasmStruct(self.loc_db, kind, self.func_name, offset))
            self._br_todo.append([])
            self._if_todo.append([])

        elif kind == 'else':
            self._structs[-1].set_else_off(self.loc_db, offset)

        elif kind == 'end':
            struct = self._structs.pop()
            struct.set_end_off(self.loc_db, offset)
            br_todo = self._br_todo.pop()
            if_todo = self._if_todo.pop()

            br_key = struct.branch_key
            for block in br_todo:
                block.bto.add(AsmConstraint(br_key, AsmConstraint.c_to))
                self._add_done(block)
            
            else_key = struct.after_else_key
            if len(if_todo) > 1:
                raise Exception('Malformed code')
            if if_todo != []:
                if_todo[0].btp.add(AsmConstraint(else_key, AsmConstraint.c_to))
                self._add_done(if_todo[0])
            
        else:
            raise Exception('{} is not a structure instruction'.format(kind))

    def add_block(self, block):
        name = block.lines[-1].name
        if name == 'if':
            if self._structs[-1].kind != 'if':
                raise Exception('Unexpected \'if\'')
            self._if_todo[-1].append(block)

        elif name == 'else':
            if self._structs[-1].kind != 'if':
                raise Exception('Unexpected \'else\'')
            # 'else' is treated as 'br 0'
            self._br_todo[-1].append(block)

        elif name in ['br', 'br_if']: # 'br_table' ?
            arg = int(block.lines[-1].getdstflow(self.loc_db))
            if arg >= len(self._br_todo):
                raise Exception('Bad br')
            self._br_todo[-1-arg].append(block)
        else:
            self._add_done(block)

    @property
    def is_done(self):
        return len(self._structs) == 0

class dis_wasm(disasmEngine): #disasmEngine):
    attrib = None

    def __init__(self, wasm_cont=None, **kwargs):
        self.cont = wasm_cont
        super(dis_wasm, self).__init__(mn_wasm, self.attrib, None, **kwargs)
        #self.dis_block_callback = cb_arm_disasm

    def dis_multiblock(self):
        raise NotImplementedError("Use dis_func_body to disassemble a function body")

    def dis_instr(self, bs, offset):
        try:
            instr = self.arch.dis(bs, self.attrib, offset)
            error = None
        except Disasm_Exception as e:
            log_asmblock.warning(e)
            instr = None
            error = AsmBlockBad.ERROR_CANNOT_DISASM
        except IOError as e:
            log_asmblock.warning(e)
            instr = None
            error = AsmBlockBad.ERROR_IO
        return instr, error

    def dis_func(self, func_idx, blocks=None):
        '''
        Disassembles a wasm function's body.
        Works sorta like the vanilla dis_multiblock except that it:
        - takes a function index @func_idx as a parameter
        - disassembles every instruction in function body
        - ignores self.dont_dis
        '''
        #log_asmblock.info("dis block all")
        func = self.cont._executable.content.functions[func_idx]

        # Get func name or create it
        func_name = func.name
        if func_name is None:
            func_name = "_function_{}".format(func_idx)

        if is_imported(func):
            res = AsmCFG(self.loc_db)
            res.add_block(AsmBlock(self.loc_db.get_or_create_name_location(func_name)))
            return res

        # Get func body
        bs = func.code.body
        cur_offset = 0
        cur_block = None

        pending_blocks = PendingBasicBlocks(self.loc_db, func_name)
        pending_blocks.structure_instr_at('func', cur_offset)
        block_cpt = 0
        ## Block loop ##
        while not pending_blocks.is_done:
            # Start new block
            block_cpt += 1
            lines_cpt = 0
            if block_cpt == 1: # Start of the function
                cur_block = AsmBlock(self.loc_db.get_or_create_name_location(func_name))
            else:
                cur_block = AsmBlock(get_loc(self.loc_db, func_name, cur_offset))

            # Check block watchdog
            if self.blocs_wd is not None and block_cpt > self.blocs_wd:
                log_asmblock.debug("blocks watchdog reached at %X in function #%X", int(cur_offset), func_idx)
                break

            ## Instruction loop ##
            while not pending_blocks.is_done:

                # Check split_dis
                # if lines_cpt > 0 and offset in self.split_dis:
                #     loc_key_cst = get_loc(self.loc_db, func_name, cur_offset)
                #     cur_block.add_cst(loc_key_cst, AsmConstraint.c_next)
                #     break
            
                lines_cpt += 1
                # Check line watchdog
                if self.lines_wd is not None and lines_cpt > self.lines_wd:
                    log_asmblock.debug("lines watchdog reached at %X", int(cur_offset))
                    break
                    
                # Try to disassemble instruction
                instr, error = self.dis_instr(bs, cur_offset)

                if instr is None:
                    log_asmblock.warning("cannot disasm at %X", int(off_i))
                    raise Exception("Disasm error: {}".format(error))
                    ''' ORIGINAL BEHAVIOUR~
                    if not cur_block.lines:
                        job_done.add(offset)
                        # Block is empty -> bad block
                        cur_block = AsmBlockBad(loc_key, errno=error)
                    else:
                        # Block is not empty, stop the desassembly pass and add a
                        # constraint to the next block
                        loc_key_cst = self.loc_db.get_or_create_offset_location(off_i)
                        cur_block.add_cst(loc_key_cst, AsmConstraint.c_next)
                    '''

                log_asmblock.debug("dis at %X in function #%X", int(cur_offset), func_idx)
                log_asmblock.debug(instr)
                log_asmblock.debug(instr.args)

                # Add instr to block
                cur_block.addline(instr)

                # Declare structure pseudo-instructions
                if instr.is_structure:
                    pending_blocks.structure_instr_at(instr.name, cur_offset)

                # Increment offset
                cur_offset += instr.l

                if not instr.breakflow():
                    continue
                
                if instr.splitflow() and not (instr.is_subcall() and self.dontdis_retcall):
                    add_next_offset = True
                    
                if add_next_offset:
                    loc_key_cst = get_loc(self.loc_db, func_name, cur_offset)
                    cur_block.add_cst(loc_key_cst, AsmConstraint.c_next)

                if self.dis_block_callback is not None:
                    self.dis_block_callback(mn=self.arch, attrib=self.attrib,
                                            pool_bin=self.bin_stream, cur_bloc=cur_block,
                                            offsets_to_dis=offsets_to_dis,
                                            loc_db=self.loc_db,
                                            # Deprecated API
                                            symbol_pool=self.loc_db)

                break

            # Register current block
            pending_blocks.add_block(cur_block)

        blocks = AsmCFG(self.loc_db)
        for block in pending_blocks.done:
            blocks.add_block(block)

        blocks.apply_splitting(self.loc_db,
                               dis_block_callback=self.dis_block_callback,
                               mn=self.arch, attrib=self.attrib,
                               pool_bin=self.bin_stream)

        return blocks
