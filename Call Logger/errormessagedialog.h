#ifndef ERRORMESSAGEDIALOG_H
#define ERRORMESSAGEDIALOG_H

#include <QMessageBox>

class ErrorMessageDialog
{
public:

    static void show(QString message)
    {
        QMessageBox errorMessage{ };

        errorMessage.setText(message);
        errorMessage.setIcon(QMessageBox::Critical);
        errorMessage.exec();
    }
};

#endif // ERRORMESSAGEDIALOG_H
