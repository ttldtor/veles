#!/usr/bin/env python3

# Copyright 2018 CodiLime
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse

parser = argparse.ArgumentParser(description='Decompile a list of functions.')
parser.add_argument('infile', help='the input file')
parser.add_argument('--outfile', help='the ouput file')
args = parser.parse_args()

from veles.data.bindata import BinData
from veles.dis.isa.falcon import FalconIsa
from veles.dis.st import IsaSTReg, IsaSTImm, IsaSTMem
from veles.deco.forest import DecoForest
from veles.deco.machine import MachineSegment, MachineBlock, MachineBaseBlock, MachineReturn, MachineEndBlock
from veles.deco.ir import IrGoto, IrCond, IrJump, IrCall, IrReturn, IrHalt
from veles.deco.struct import StructFunc

CPP_TEMPLATE = """
#include "ui/disasm/disasm.h"
#include "ui/disasm/mocks.h"
#include "ui/disasm/gf100.h"

namespace veles {{
namespace ui {{
namespace disasm {{
namespace mocks{{

{blob_class}::{blob_class}() {{
}}

std::unique_ptr<ChunkMeta> {blob_class}::make_chunk(ChunkID id,
                                                    ChunkID parent,
                                                    Bookmark pos_begin,
                                                    Bookmark pos_end,
                                                    Address addr_begin,
                                                    Address addr_end,
                                                    QString type,
                                                    ChunkType meta_type,
                                                    QString display_name,
                                                    std::unique_ptr<TextRepr> text_repr,
                                                    QString comment) {{
        auto chunk = std::make_unique<ChunkMeta>();
        chunk->id = id;
        chunk->parent_id = parent;
        chunk->pos_begin = pos_begin;
        chunk->pos_end = pos_end;
        chunk->addr_begin = addr_begin;
        chunk->addr_end = addr_end;
        chunk->type = type;
        chunk->display_name = display_name;
        chunk->text_repr = std::move(text_repr);
        chunk->comment = comment;
        chunk->collapsed = true;
        chunk->meta_type = meta_type;

        return chunk;
  }}

std::unique_ptr<ChunkNode> {blob_class}::gibRoot() {{
{TEXT_REPRESENTATIONS}
{CHUNKS}
{CHUNK_NODES}
return {ROOT_CHUNK_NODE};
}}

}}
}}
}}
}}
"""

def make_prefixer(pref):
    cnt = 0
    def doit():
        nonlocal cnt
        cnt += 1
        return pref + str(cnt)
    return doit

def qsurround(s):
    return '"' + s + '"'


class TextRepr:

    next_var = make_prefixer("var_trepr_")

    def __init__(self):
        self.name = TextRepr.next_var()

    @classmethod
    def make_text(cls, text, highlight):
        tr = cls()
        tr.klass = "Text"
        tr.args = ", ".join(
            [qsurround(text), "true" if highlight else "false"])
        return tr

    @classmethod
    def make_keyword(cls, text, type, link):
        assert(type in ["OPCODE", "MODIFIER", "LABEL", "REGISTER"])
        type = "KeywordType::" + type
        tr = cls()
        tr.klass = "Keyword"
        tr.args = ", ".join([qsurround(text), type, qsurround(link)])
        return tr

    @classmethod
    def make_blank(cls):
        tr = cls()
        tr.klass = "Blank"
        tr.args = ""
        return tr

    @classmethod
    def make_number(cls, val, width, base):
        tr = cls()
        tr.klass = "Number"
        tr.args = ", ".join(map(str, [val, width, base or 16]))
        return tr

    @classmethod
    def make_sublist(cls, args):
        assert all(map(lambda el: isinstance(el, TextRepr), args))
        tr = cls()
        tr.klass = "Sublist"
        # let's hope that it's gonna work
        tr.args = "{" \
                + ", ".join(map(lambda arg : arg.var_name(), args)) \
                + "}"
        return tr

    def var_name(self):
        return self.name

    def decl_str(self):
        return f"auto {self.name} = new {self.klass}({self.args});"

    def __str__(self):
        return f"TextRepr({self.args})"


class Chunk:

    next_var = make_prefixer("var_chunk_")
    next_chunk_node = make_prefixer("var_chunk_node_")
    next_id = make_prefixer("chk_id_")

    def __init__(self, parent, addr_beg, addr_end, type, disp_name, repr, comm):
        self.name = Chunk.next_var()
        self.id = Chunk.next_id()
        self.chunk_node = Chunk.next_chunk_node()

        self.parent = parent
        if isinstance(parent, Chunk):
            parent.children.append(self)

        self.children = []

        # TODO(chivay) well it shouldn't be empty
        self.pos_beg = ""
        self.pos_end = ""

        self.addr_beg = addr_beg
        self.addr_end = addr_end
        self.type = type
        self.display_name = disp_name
        self.text_repr = repr
        self.comment = comm


    def decl_str(self):
        args = ", ".join([qsurround(self.id),
                          qsurround(self.parent.id if self.parent else ""),
                          qsurround(self.pos_beg),
                          qsurround(self.pos_end),
                          str(self.addr_beg),
                          str(self.addr_end),
                          qsurround(self.type),
                          "ChunkType::" + self.type,
                          qsurround(self.display_name),
                          "std::move(std::unique_ptr<TextRepr>("+ self.text_repr.var_name() + "))",
                          qsurround(self.comment)])
        return "\n".join([f"auto {self.name} = make_chunk({args});",
                          f"auto {self.chunk_node} = std::make_unique<ChunkNode>(std::move({self.name}));"])

    def var_name(self):
        return self.name

    def __str__(self):
        return f"Chunk({self.type}, {self.addr_beg}:{self.addr_end})"


class VelesCppGen:

    def __init__(self, filename, template, forest, data, flat_bundles=True):
        self.flat_bundles = flat_bundles
        self.cpp_template = template
        self.filename = filename

        self.chunks = []
        self.text_repr = []

        t = TextRepr.make_text("File Chunk", False)
        self.text_repr.append(t)

        self.file_chunk = Chunk(None, None, None, "FILE", "File", t, "")
        self.chunks.append(self.file_chunk)

        for tree in forest.trees:
            self.process_block(tree.root, self.file_chunk)


        self.fix_chunk(self.file_chunk)

    def fix_chunk(self, chunk):
        if chunk.addr_beg is None or chunk.addr_end is None:
            for child in chunk.children:
                self.fix_chunk(child)

            chunk.addr_beg = min(map(lambda c: c.addr_beg, chunk.children))
            chunk.addr_end = max(map(lambda c: c.addr_end, chunk.children))

    def add_chunk(self, c):
        assert(isinstance(c, Chunk))
        self.chunks.append(c)

    def add_text_repr(self, t):
        assert(isinstance(t, TextRepr))
        self.text_repr.append(t)

    def ins_to_repr(self, ins):
        # TODO(chivay): no link!
        opcode = TextRepr.make_keyword(ins.name, "OPCODE", "")
        blank = TextRepr.make_blank()

        args = [opcode, blank]
        for arg in ins.args:
            if len(args) > 2:
                args.append(TextRepr.make_text(",", False))
                args.append(TextRepr.make_blank())

            if isinstance(arg, IsaSTReg):
                reg = TextRepr.make_keyword(str(arg), "REGISTER", "")
                args.append(reg)
            elif isinstance(arg, IsaSTImm):
                num = TextRepr.make_number(arg.val, arg.width, arg.base)
                args.append(num)
            elif isinstance(arg, IsaSTMem):
                # TODO(chivay): handle it gracefully
                placeholder = TextRepr.make_text(str(arg), True)
                args.append(placeholder)
            else:
                raise NotImplementedError(repr(arg))

        for arg in args:
            self.text_repr.append(arg)

        return TextRepr.make_sublist(args)

    def process_block(self, block, parent_chunk):
        """ Process and add basic block to output """
        if isinstance(block, MachineEndBlock):
            # Process children
            for child in block.children:
                self.process_block(child, parent_chunk)
            return
        t = TextRepr.make_text(block.get_name(), False)
        block_chunk = Chunk(parent_chunk, None, None,
                            "BASIC_BLOCK", block.get_name(), t, "")
        self.add_text_repr(t)
        self.add_chunk(block_chunk)

        for parse_result in block.raw_insns:
            start = parse_result.start
            end = parse_result.end

            if not self.flat_bundles:
                t = TextRepr.make_text("Bundle", False)
                bundle_chunk = Chunk(block_chunk, start, end,
                                     "BUNDLE", "Bundle", t, "")
                ins_parent = bundle_chunk
                self.add_text_repr(t)
                self.add_chunk(bundle_chunk)
            else:
                ins_parent = block_chunk


            # TODO(chivay): we should know about instruction length
            #               patch dynamite maybe?
            ins_len = (end - start) // len(parse_result.insns)

            for ins, st in zip(parse_result.insns, range(start, end, ins_len)):
                repr = self.ins_to_repr(ins)
                chk = Chunk(ins_parent, st, st + ins_len,
                            "INSTRUCTION", "Instruction", repr, "")
                self.add_chunk(chk)
                self.add_text_repr(repr)


        # Process children
        for child in block.children:
            self.process_block(child, parent_chunk)


    def text_reprs_str(self):
        return "\n".join(map(lambda r: r.decl_str(), self.text_repr))

    def chunks_str(self):
        return "\n".join(map(lambda r: r.decl_str(), self.chunks))

    def entry_gen_str(self):
        entry_fmt = "entries_.emplace_back(std::make_shared<{klass}>({chunk}));"
        def chunk_traverse(chunk, entries):
            if chunk.children:
                entries.append(entry_fmt.format(klass="EntryChunkBegin", chunk=chunk.var_name()))
                for child in chunk.children:
                    chunk_traverse(child, entries)
                entries.append(entry_fmt.format(klass="EntryChunkEnd", chunk=chunk.var_name()))
            else:
                entries.append(entry_fmt.format(klass="EntryChunkCollapsed", chunk=chunk.var_name()))

        entries_arr = []
        chunk_traverse(self.file_chunk, entries_arr)

        return "\n".join(entries_arr)

    def chunk_nodes_str(self):
        rep = []
        def chunk_traverse(chunk, arr):
            for child in chunk.children:
                chunk_traverse(child, arr)
                rep.append("{var}->addChild(std::move({child}));".format(var=chunk.chunk_node, child=child.chunk_node))
        chunk_traverse(self.file_chunk, rep)
        return "\n".join(rep)

    def build_string(self):
        vars = {
            'name': self.filename.replace('.', '_'),
        }

        vars['window_class'] = "Mock_{name}_Window".format(**vars)
        vars['blob_class'] = "Mock_{name}".format(**vars)

        vars['TEXT_REPRESENTATIONS'] = self.text_reprs_str()
        vars['CHUNKS'] = self.chunks_str()
        vars['CHUNK_NODES'] = self.chunk_nodes_str()
        vars['ROOT_CHUNK_NODE'] = self.file_chunk.chunk_node

        return self.cpp_template.format(**vars)


if __name__ == '__main__':
    cppgen = VelesCppGen(args.infile, CPP_TEMPLATE, forest, data,
                         flat_bundles = True)
    if args.outfile:
        with open(args.outfile, "w") as f:
            f.write(cppgen.build_string())
    else:
        print(cppgen.build_string())


# forest.process()
# forest.post_process()
