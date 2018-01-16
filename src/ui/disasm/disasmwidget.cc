#include "ui/disasm/disasmwidget.h"
#include "ui/disasm/disasm.h"
#include "ui/disasm/mocks.h"

namespace veles {
namespace ui {

using namespace disasm;
using namespace mocks;

std::ostream& hex_print(std::ostream& os, int64_t x) {
  return os << "0x" << std::setfill('0') << std::setw(4) << std::hex << x
            << std::dec;
}

std::string fieldStringRepresentation(EntryField* field_entry) {
  switch (field_entry->field_type) {
    case FieldType::STRING: {
      auto* fvs = reinterpret_cast<FieldValueString*>(field_entry->value.get());
      return fvs->value.toStdString();
    }
    default: { break; }
  }
  return "[CANNOT DISPLAY AS STRING]";
}

std::stringstream& operator<<(std::stringstream& os, Entry* entry) {
  switch (entry->type()) {
    case EntryType::CHUNK_BEGIN: {
      auto* ent = reinterpret_cast<EntryChunkBegin*>(entry);
      hex_print(os, ent->chunk->addr_begin);
      os << " ChunkBegin(id: " << ent->chunk->id.toStdString()
         << ", type: " << ent->chunk->type.toStdString() << ")";
      break;
    }
    case EntryType::CHUNK_END: {
      auto* ent = reinterpret_cast<EntryChunkEnd*>(entry);
      hex_print(os, ent->chunk->addr_end);
      os << " ChunkEnd(id: " << ent->chunk->id.toStdString() << ")";
      break;
    }
    case EntryType::OVERLAP: {
      os << "Overlap()";
      break;
    }
    case EntryType::FIELD: {
      auto* ent = reinterpret_cast<EntryField*>(entry);
      os << fieldStringRepresentation(ent);
      break;
    }
    default:
      os << "[UNKNOWN]";
  }
  return os;
}

std::stringstream entry_printer(
    const std::vector<std::shared_ptr<Entry>>& entries) {
  std::stringstream out;
  int indent = 0;
  for (auto& entry : entries) {
    auto e = entry.get();
    if (e->type() == EntryType::CHUNK_END) indent--;
    for (int i = 0; i < indent; i++) out << "  ";
    out << e << std::endl;
    if (e->type() == EntryType::CHUNK_BEGIN) indent++;
  }
  return out;
}

DisasmWidget::DisasmWidget() {
  address_column.setAddressVector({1,  2,  3,  4,  5,  6,  7,  8,
                                   9,  10, 11, 12, 13, 14, 15, 16,
                                   17, 18, 19, 20, 21, 22, 23, 24});

  address_column.setHintMap({{13, 2}, {23, 5}});
  address_column.setFixedWidth(100);  // todo(zpp) fix it somewhen

  rich_text_widget.setReadOnly(true);
  rich_text_widget.setAcceptRichText(true);

  ChunkTreeFactory ctf;
  std::unique_ptr<ChunkNode> root = ctf.generateTree(ChunkType::FILE);
  ctf.setAddresses(root.get(), 0, 0x1000);
  std::shared_ptr<ChunkNode> sroot{root.release()};
  MockBlob blob(sroot);
  auto entrypoint_future = blob.getEntrypoint();
  auto entrypoint = entrypoint_future.result();
  std::unique_ptr<Window> window = blob.createWindow(entrypoint, 2, 10);
  std::stringstream out = entry_printer(window->entries());

  rich_text_widget.setText(out.str().c_str());

  main_layout.addWidget(&address_column);
  main_layout.addWidget(&rich_text_widget);
  setLayout(&main_layout);
}

}  // namespace ui
}  // namespace veles
