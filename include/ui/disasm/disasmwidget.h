#pragma once

#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QTextEdit>
#include "richtextwidget.h"
#include "ui/disasm/addresscolumn.h"

namespace veles {
namespace ui {

/*
 * Container for component widgets (address column, hex column, etc).
 * Responsible for rendering them in right position.
 */
class DisasmWidget : public QWidget {
  Q_OBJECT
  QHBoxLayout main_layout;
  AddressColumnWidget address_column;
  QTextEdit rich_text_widget;

 public:
  DisasmWidget();
};

}  // namespace ui
}  // namespace veles
