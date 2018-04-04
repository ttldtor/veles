/*
 * Copyright 2018 CodiLime
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "ui/disasm/widget.h"

namespace veles {
namespace ui {
namespace disasm {

Widget::Widget() {
  setWidgetResizable(true);
  setFont(util::settings::theme::font());

  arrows_ = new Arrows;

  rows_layout_ = new QVBoxLayout();
  rows_layout_->setSpacing(0);
  rows_layout_->setContentsMargins(0, 0, 0, 0);

  auto rows_with_stretch = new QVBoxLayout();
  rows_with_stretch->setSpacing(0);
  rows_with_stretch->setContentsMargins(0, 0, 0, 0);
  rows_with_stretch->addLayout(rows_layout_);
  rows_with_stretch->addStretch();

  auto split_layout = new QHBoxLayout;
  split_layout->setSpacing(0);
  split_layout->setMargin(0);
  split_layout->addWidget(arrows_, 0, Qt::AlignTop);
  split_layout->addLayout(rows_with_stretch, 0);

  split_layout->setSizeConstraint(QLayout::SetDefaultConstraint);

  auto split_view = new QWidget;
  split_view->setLayout(split_layout);

  setWidget(split_view);

  scroll_bar_ = new QScrollBar(this);
  setVerticalScrollBar(scroll_bar_);
  setVerticalScrollBarPolicy(Qt::ScrollBarPolicy::ScrollBarAlwaysOn);

  scroll_bar_->setSingleStep(ROW_HEIGHT);
  scroll_bar_->setPageStep(ROW_HEIGHT*50);
  scroll_bar_->setTracking(false);

  connect(scroll_bar_, &QScrollBar::valueChanged, this,
          &Widget::scrollbarChanged);

  setupMocks();
  getEntrypoint();
}

void Widget::scrollbarChanged(int value) {
  std::cerr << "Widget::scrollbarChanged: value=" << value << std::endl;

  mutex_.lock();
  scroll_bar_index_ = value / ROW_HEIGHT;
  std::cerr << "Widget::scrollbarChanged: scroll index=" << scroll_bar_index_ << std::endl;

  auto window_index_ = window_->currentScrollbarIndex();
  if (abs(window_index_ - scroll_bar_index_) > 150) {
    auto pos = blob_->getPosition(scroll_bar_index_);
    pos.waitForFinished();

    window_->seek(pos.result(), 500, 500);
    generateRows(window_->entries());

    std::cerr << "Widget::scrollContentsBy: generating rows" << std::endl;
  }
  mutex_.unlock();

  viewport()->update();
}

void Widget::setupMocks() {
  mocks::ChunkTreeFactory ctf;

  std::unique_ptr<mocks::ChunkNode> root =
      ctf.generateTree(mocks::ChunkType::FILE);
  ctf.setAddresses(root.get(), 0, 0x1000);

  std::shared_ptr<mocks::ChunkNode> sroot{root.release()};

  std::unique_ptr<mocks::MockBlob> mb =
      std::make_unique<mocks::MockBlob>(sroot);
  blob_ = std::unique_ptr<Blob>(std::move(mb));
}

void Widget::getEntrypoint() {
  entrypoint_ = blob_->getEntrypoint();

  entrypoint_watcher_.setFuture(entrypoint_);

  connect(&entrypoint_watcher_, &QFutureWatcher<Bookmark>::finished, this,
          &Widget::getWindow);
}

void Widget::getWindow() {
  entrypoint_.waitForFinished();
  Bookmark entrypoint = entrypoint_.result();

  window_ = blob_->createWindow(entrypoint, 500, 500);
  connect(window_.get(), &Window::dataChanged, this, &Widget::updateRows);

  std::cerr << "Widget::GetWindow: got window" << std::endl;

  auto max_height = (int)window_->maxScrollbarIndex();
  if (max_height < 0) {
    max_height = 0;
  }

  auto index = window_->currentScrollbarIndex();

  verticalScrollBar()->setRange(0, max_height*ROW_HEIGHT);
  verticalScrollBar()->setValue(index*ROW_HEIGHT);

  std::cerr << "Widget::GetWindow: Range: 0-" << max_height
        << "; Value: " << index << std::endl;
}

void Widget::updateRows() {
  generateRows(window_->entries());
}

void Widget::generateRows(std::vector<std::shared_ptr<Entry>> entries) {
  while (rows_.size() < entries.size()) {
    auto r = new Row();
    rows_layout_->addWidget(r, 0, Qt::AlignTop);
    rows_.push_back(r);

    connect(r, &Row::chunkCollapse, this, &Widget::chunkCollapse);
  }

  Row* row;
  while (rows_.size() > entries.size()) {
    row = rows_.back();
    rows_.pop_back();
    rows_layout_->removeWidget(row);
    delete row;
  }

  int indent_level = 0;
  for (size_t i = 0; i < entries.size(); i++) {
    auto entry = entries[i];
    row = static_cast<Row*>(rows_layout_->itemAt(i)->widget());

    switch (entry->type()) {
      case EntryType::CHUNK_COLLAPSED: {
        auto* ent = static_cast<EntryChunkCollapsed const*>(entry.get());
        row->setEntry(ent);
        row->setIndent(indent_level);
        break;
      }
      case EntryType::CHUNK_BEGIN: {
        auto* ent = static_cast<EntryChunkBegin const*>(entry.get());
        row->setEntry(ent);
        row->setIndent(indent_level);
        indent_level++;
        break;
      }
      case EntryType::CHUNK_END: {
        indent_level--;
        auto* ent = static_cast<EntryChunkEnd const*>(entry.get());
        row->setEntry(ent);
        row->setIndent(indent_level);
        break;
      }
      case EntryType::OVERLAP: {
        auto* ent = static_cast<EntryOverlap const*>(entry.get());
        row->setEntry(ent);
        row->setIndent(indent_level);
        break;
      }
      case EntryType::FIELD: {
        auto* ent = static_cast<EntryField const*>(entry.get());
        row->setEntry(ent);
        row->setIndent(indent_level);
        break;
      }
      default: { break; }
    }
  }
}
void Widget::toggleColumn(Row::ColumnName column_name) {
  auto rows = this->findChildren<Row*>();
  std::for_each(rows.begin(), rows.end(),
                [&column_name](Row* row) { row->toggleColumn(column_name); });
}

void Widget::chunkCollapse(const ChunkID& id) {
  window_->chunkCollapseToggle(id);
}

}  // namespace disasm
}  // namespace ui
}  // namespace veles
