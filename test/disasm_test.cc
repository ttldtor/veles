#include <iomanip>
#include <iostream>

#include "ui/disasm/asmgen.h"
#include "ui/disasm/mocks.h"

std::ostream& hex_print(std::ostream& os, int64_t x) {
  return os << "0x" << std::setfill('0') << std::setw(4) << std::hex << x
            << std::dec;
}

using veles::ui::disasm::Entry;
using veles::ui::disasm::EntryChunkBegin;
using veles::ui::disasm::EntryChunkEnd;
using veles::ui::disasm::EntryField;
using veles::ui::disasm::EntryType;
using veles::ui::disasm::FieldType;
using veles::ui::disasm::FieldValueString;
using veles::ui::disasm::Window;
using veles::ui::disasm::EntryFieldStringRepresentation;
using veles::ui::disasm::mocks::ChunkTreeFactory;
using veles::ui::disasm::mocks::ChunkType;
using veles::ui::disasm::mocks::ChunkNode;
using veles::ui::disasm::mocks::ChunkMeta;
using veles::ui::disasm::mocks::EntryFactory;
using veles::ui::disasm::mocks::MockWindow;
using veles::ui::disasm::mocks::MockBlob;

std::ostream& operator<<(std::ostream& os, Entry* entry) {
  switch (entry->type()) {
    case EntryType::CHUNK_BEGIN: {
      auto* ent = static_cast<EntryChunkBegin*>(entry);
      hex_print(os, ent->chunk->addr_begin);
      os << " ChunkBegin(id: " << ent->chunk->id.toStdString()
         << ", type: " << ent->chunk->type.toStdString() << ") ";
      os << ent->chunk->text_repr->string().toStdString();
      break;
    }
    case EntryType::CHUNK_END: {
      auto* ent = static_cast<EntryChunkEnd*>(entry);
      hex_print(os, ent->chunk->addr_end);
      os << " ChunkEnd(id: " << ent->chunk->id.toStdString() << ")";
      break;
    }
    case EntryType::OVERLAP: {
      os << "Overlap()";
      break;
    }
    case EntryType::FIELD: {
      auto* ent = static_cast<EntryField*>(entry);
      os << EntryFieldStringRepresentation(ent);
      break;
    }
    default:
      os << "[UNKNOWN]";
  }
  return os;
}

void entry_printer(const std::vector<std::shared_ptr<Entry>>& entries) {
  int indent = 0;
  for (auto& entry : entries) {
    auto e = entry.get();
    if (e->type() == EntryType::CHUNK_END) indent--;
    for (int i = 0; i < indent; i++) std::cerr << "  ";
    std::cerr << e << std::endl;
    if (e->type() == EntryType::CHUNK_BEGIN) indent++;
  }
}

int main() {}
