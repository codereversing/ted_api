#ifndef MODULESLISTWINDOW_H
#define MODULESLISTWINDOW_H

#include <QDialog>

#include <QMap>
#include <QPair>
#include <QSet>
#include <QString>

#include "numerictablewidgetitem.h"

#include "thirdparty/include/TEDClientBridge.h"

namespace Ui {
class ModulesListWindow;
}

class ModulesListWindow : public QDialog
{
    Q_OBJECT

public:
    explicit ModulesListWindow(TED_Client *      client,
      QSet<QString> *                            activeModules,
      QMap<QPair<uint64_t, uint64_t>, QString> * moduleAddressRanges,
      QWidget *                                  parent = nullptr);

    ~ModulesListWindow();

private slots:
    void on_pushButton_Close_clicked();
    void on_pushButton_Log_calls_clicked();
    void on_pushButton_Stop_logging_calls_clicked();

private:
    Ui::ModulesListWindow * ui;

    void refreshModules();

    TED_Client * m_client;

    QSet<QString> * m_activeModules;
    QMap<QPair<uint64_t, uint64_t>, QString> * m_moduleAddressRanges;

    QMap<QString, QString> m_moduleNamesMap;
};

#endif // MODULESLISTWINDOW_H
