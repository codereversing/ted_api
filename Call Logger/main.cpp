#include "mainwindow.h"

#include <QApplication>

#include "thirdparty/include/TEDClientBridge.h"

int main(int argc, char * argv[])
{
    if (!TED_LoadClientAPI("TEDClientAPI.dll")) {
        MessageBoxA(nullptr, "TEDClientAPI.dll was not found!", "Error", MB_ICONEXCLAMATION);
        exit(-1);
    }

    TED_ResolveClientFunctions(GetModuleHandleA("TEDClientAPI.dll"));

    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
