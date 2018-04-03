#pragma once
#include "ui/disasm/disasm.h"
#include "ui/disasm/mocks.h"
namespace veles {
namespace ui {
namespace disasm {
namespace mocks {

class Mock_test_map : public MockBackend {
 public:
  explicit Mock_test_map();
  std::unique_ptr<ChunkMeta> make_chunk(ChunkID id, ChunkID parent,
                                        Bookmark pos_begin, Bookmark pos_end,
                                        Address addr_begin, Address addr_end,
                                        QString type, ChunkType meta_type,
                                        QString display_name,
                                        std::unique_ptr<TextRepr> text_repr,
                                        QString comment);

  std::unique_ptr<ChunkNode> gibRoot();

 private:
  std::unique_ptr<ChunkNode> root_;
};
}
}
}
}
