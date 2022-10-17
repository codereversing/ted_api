#ifndef BREAKPOINTINFOWINDOW_H
#define BREAKPOINTINFOWINDOW_H

#include <memory>

#include <QDialog>

#include "thirdparty/include/TEDClientBridge.h"

namespace Ui {
class BreakpointInfoWindow;
}

class BreakpointInfoWindow : public QDialog
{
    Q_OBJECT

public:
    explicit BreakpointInfoWindow(std::shared_ptr<TED_BreakpointResponse> response, QWidget * parent = nullptr);
    ~BreakpointInfoWindow();

private slots:
    void on_pushButton_Close_clicked();

private:
    Ui::BreakpointInfoWindow * ui;

    void displayInfo(std::shared_ptr<TED_BreakpointResponse> response);
};

#endif // BREAKPOINTINFOWINDOW_H
