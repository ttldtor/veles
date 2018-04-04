/*
 * Copyright 2016 CodiLime
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
#include <QApplication>
#include <QHostAddress>
#include <QSurfaceFormat>
#include <QTranslator>
#include <include/ui/docks/dock.h>

#include "ui/dockwidget.h"
#include "ui/veles_mainwindow.h"
#include "ui/velesapplication.h"
#include "util/concurrency/threadpool.h"
#include "util/settings/theme.h"
#include "util/version.h"
#include "visualization/base.h"
#include "visualization/digram.h"
#include "visualization/trigram.h"

int main(int argc, char* argv[]) {
  Q_INIT_RESOURCE(veles);

  QSurfaceFormat format;
  format.setDepthBufferSize(24);
  format.setVersion(3, 3);
  format.setProfile(QSurfaceFormat::CoreProfile);
  QSurfaceFormat::setDefaultFormat(format);

  QApplication::setAttribute(Qt::AA_ShareOpenGLContexts);

  // *Do not* change the type of `app`, otherwise VelesApplication::instance
  // will break.
  veles::ui::VelesApplication app(argc, argv);

  QApplication::setApplicationName("Veles");
  QApplication::setOrganizationName("CodiSec");
  QApplication::setApplicationVersion(veles::util::version::string);

  QApplication::setStyle(veles::util::settings::theme::createStyle());
  QApplication::setPalette(veles::util::settings::theme::palette());

  // Identify locale and load translation if available
  QString locale = QLocale::system().name();
  QTranslator translator;
  translator.load(QString("hexedit_") + locale);
  QApplication::installTranslator(&translator);

  veles::util::threadpool::createTopic("visualization", 3);

  qRegisterMetaType<
      veles::visualization::VisualizationWidget::AdditionalResampleDataPtr>(
      "AdditionalResampleDataPtr");
  qRegisterMetaType<veles::client::NetworkClient::ConnectionStatus>(
      "veles::client::NetworkClient::ConnectionStatus");

  QCommandLineParser parser;
  parser.addHelpOption();
  parser.addVersionOption();
  parser.process(app);

  auto* mainWin = new veles::ui::VelesMainWindow;
  mainWin->showMaximized();

  QLabel * label = new QLabel("Ala ma kota");
  QLabel * label2 = new QLabel("Ala ma kota3");
  auto* splitWin = new veles::ui::Dock;
  splitWin -> showMaximized();
  splitWin -> addWidget(label, "", veles::ui::DropArea::Center);
  splitWin -> addWidget(label2, "labelka 2", veles::ui::DropArea::Left);

  QLabel * label3 = new QLabel("Ala ma kota w Tabach");
  QLabel * label4 = new QLabel("Ala ma kota3 w Tabach");
  auto* tabWin = new veles::ui::Dock;
  tabWin -> showMaximized();
  tabWin -> addWidget(label3, QIcon(":/images/show_hex_edit.png"), "", veles::ui::DropArea::Center);
  tabWin -> addWidget(label4, QIcon(":/images/show_hex_edit.png"), "labelka 2", veles::ui::DropArea::Center);

  auto files = parser.positionalArguments();
  for (const auto& file : files) {
    mainWin->addFile(file);
  }

  return QApplication::exec();
}
