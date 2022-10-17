#include "breakpointinfowindow.h"
#include "ui_breakpointinfowindow.h"

BreakpointInfoWindow::BreakpointInfoWindow(std::shared_ptr<TED_BreakpointResponse> response, QWidget * parent) :
    QDialog(parent),
    ui(new Ui::BreakpointInfoWindow)
{
    ui->setupUi(this);

    displayInfo(response);
}

BreakpointInfoWindow::~BreakpointInfoWindow()
{
    delete ui;
}

void BreakpointInfoWindow::displayInfo(std::shared_ptr<TED_BreakpointResponse> response)
{
    auto text{
        QString("Read breakpoint event\nProcess ID: %1\nThread ID: %2\nSource Address: %3\nDestination Address: %4\n\n")
        .arg(response->processId)
        .arg(response->threadId)
        .arg(QString::number(response->sourceAddress, 16).toUpper())
        .arg(QString::number(response->destinationAddress, 16).toUpper())
    };

    text += QString("Context\nRAX: %1\nRBX: %2\nRCX: %3\nRDX: %4\nRSP: %5\nRBP: %6\nRSI: %7\nRDI: %8\n")
      .arg(QString::number(response->context.generalRegisters.rax, 16).toUpper())
      .arg(QString::number(response->context.generalRegisters.rbx, 16).toUpper())
      .arg(QString::number(response->context.generalRegisters.rcx, 16).toUpper())
      .arg(QString::number(response->context.generalRegisters.rdx, 16).toUpper())
      .arg(QString::number(response->context.generalRegisters.rsp, 16).toUpper())
      .arg(QString::number(response->context.generalRegisters.rbp, 16).toUpper())
      .arg(QString::number(response->context.generalRegisters.rsi, 16).toUpper())
      .arg(QString::number(response->context.generalRegisters.rdi, 16).toUpper());

    text += QString("RIP: %1\n")
      .arg(QString::number(response->context.generalRegisters.rip, 16).toUpper());

    text += QString("R8: %1\nR9: %2\nR10: %3\nR11: %4\nR12: %5\nR13: %6\nR14: %7\nR15: %8\n\n")
      .arg(QString::number(response->context.generalRegistersx64.r8, 16).toUpper())
      .arg(QString::number(response->context.generalRegistersx64.r9, 16).toUpper())
      .arg(QString::number(response->context.generalRegistersx64.r10, 16).toUpper())
      .arg(QString::number(response->context.generalRegistersx64.r11, 16).toUpper())
      .arg(QString::number(response->context.generalRegistersx64.r12, 16).toUpper())
      .arg(QString::number(response->context.generalRegistersx64.r13, 16).toUpper())
      .arg(QString::number(response->context.generalRegistersx64.r14, 16).toUpper())
      .arg(QString::number(response->context.generalRegistersx64.r15, 16).toUpper());

    text += QString("DR0: %1\nDR1: %2\nDR2: %3\nDR3: %4\nDR6: %5\nDR7: %6\n\n")
      .arg(QString::number(response->context.debugRegisters.dr0, 16).toUpper())
      .arg(QString::number(response->context.debugRegisters.dr1, 16).toUpper())
      .arg(QString::number(response->context.debugRegisters.dr2, 16).toUpper())
      .arg(QString::number(response->context.debugRegisters.dr3, 16).toUpper())
      .arg(QString::number(response->context.debugRegisters.dr6, 16).toUpper())
      .arg(QString::number(response->context.debugRegisters.dr7, 16).toUpper());

    text += QString("CS: %1\nDS: %2\nES: %3\nFS: %4\nGS: %5\nSS: %6\n\n")
      .arg(QString::number(response->context.segmentRegisters.cs, 16).toUpper())
      .arg(QString::number(response->context.segmentRegisters.ds, 16).toUpper())
      .arg(QString::number(response->context.segmentRegisters.es, 16).toUpper())
      .arg(QString::number(response->context.segmentRegisters.fs, 16).toUpper())
      .arg(QString::number(response->context.segmentRegisters.gs, 16).toUpper())
      .arg(QString::number(response->context.segmentRegisters.ss, 16).toUpper());

    text += "Call stack\n";
    if (response->callStack.stackFramesCount > 0) {
        for (size_t i{ 0 }; i < response->callStack.stackFramesCount; i++) {
            const auto * stackFrame = response->callStack.stackFrames[i];
            text += QString("RIP: %1\nReturn Address: %2\nFrame Pointer: %3\nStack Pointer: %4\n")
              .arg(QString::number(stackFrame->rip, 16).toUpper())
              .arg(QString::number(stackFrame->returnAddress, 16).toUpper())
              .arg(QString::number(stackFrame->framePointer, 16).toUpper())
              .arg(QString::number(stackFrame->stackPointer, 16).toUpper());

            text += QString("Parameters\nParam 1: %1\nParam 2: %2\nParam 3: %3\nParam 4: %4\n")
              .arg(QString::number(stackFrame->parameters[0], 16).toUpper())
              .arg(QString::number(stackFrame->parameters[1], 16).toUpper())
              .arg(QString::number(stackFrame->parameters[2], 16).toUpper())
              .arg(QString::number(stackFrame->parameters[3], 16).toUpper());

            if (stackFrame->symbols.functionNameLength > 0) {
                text += QString("Function name: %1\n")
                  .arg(stackFrame->symbols.functionName);
            }

            text += "\n";
        }
    }

    this->ui->textEdit_Breakpoint_info->setText(text);
}

void BreakpointInfoWindow::on_pushButton_Close_clicked()
{
    this->close();
}
