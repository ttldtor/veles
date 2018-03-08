#pragma once

#include <memory>
#include <QtWidgets/QWidget>
#include <QtWidgets/QBoxLayout>
#include <QtWidgets/QStackedLayout>
#include <QtWidgets/QTabBar>
#include <QtCore/QPointer>
#include <QtWidgets/QSplitter>

namespace veles {
namespace ui {

enum DropArea
{
  Invalid = 0,
  Top = 1,
  Right = 2,
  Bottom = 4,
  Left = 8,
  Center = 16,

  AllAreas = Top | Right | Bottom | Left | Center,
  Sides = Right | Left,
  Sth = Top | Bottom,
  NotCenter = Sides | Sth
};

Q_DECLARE_FLAGS(DropAreas, DropArea)


class Dock : public QWidget {

  Q_OBJECT

 public:

  explicit Dock(QWidget *parent = nullptr);

  void addWidget(QWidget * widget, const QString& label, DropArea area = DropArea::Center);
  enum DockState {Empty = 0, Consistent = 1, Divided = 2};

  void setState(DockState state);

 public slots:
  void dockStateChange(DockState new_state, Dock * child);

 signals:
  void stateChanged(DockState new_state);

 private:
  DockState state;
  Qt::Orientation orientation;
  QVector<QWidget *> stacked_widgets;

  QVBoxLayout * top_layout;
  QStackedLayout * stacked_layout;
  QSplitter * splitter;
  QTabBar * tab_bar;
  QPointer<Dock> dock1, dock2;

  void updateTabBar(QWidget * added, const QString& label, const QIcon& icon);
  void updateTabBar(QWidget * added, const QString& label);
  void updateTabBar();
  void initDocks();
  void clearDocks();

};

}
} //veles