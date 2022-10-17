#include "memorywindow.h"
#include "thirdparty/include/Structures.h"
#include "ui_memorywindow.h"

#include <array>

#include <QByteArray>
#include <QStringList>

#include "errormessagedialog.h"

MemoryWindow::MemoryWindow(TED_Client * client, QWidget * parent) :
    QDialog(parent),
    ui(new Ui::MemoryWindow)
    , m_client{client}
    , m_previousByteValues{}
{
    ui->setupUi(this);

    ui->tableWidget_Bytes->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    ui->tableWidget_Bytes->resizeColumnsToContents();
}

MemoryWindow::~MemoryWindow()
{
    delete ui;
}

void MemoryWindow::on_pushButton_Close_clicked()
{
    this->close();
}

void MemoryWindow::on_pushButton_Save_clicked()
{
    bool validAddress{ };
    auto address{ this->ui->lineEdit_Address->text().toULongLong(&validAddress, 16) };

    if (validAddress) {
        QMap<uint64_t, unsigned char> writeBytesMap{ };
        uint64_t writeOffset{ };
        for (auto i{ 0 }; i < this->ui->tableWidget_Bytes->rowCount(); i++) {
            for (auto j{ 1 }; j < this->ui->tableWidget_Bytes->columnCount(); j++) {
                auto currentByte{ this->ui->tableWidget_Bytes->item(i, j) };
                if (currentByte->background() == Qt::red) {
                    auto byteArray{ QByteArray::fromHex(
                                        this->ui->tableWidget_Bytes->item(i, j)->text().toUtf8()) };
                    writeBytesMap[address + writeOffset] = static_cast<unsigned char>(byteArray.at(0));
                }

                writeOffset++;
            }
        }

        foreach(const auto& writeAddress, writeBytesMap.keys()){
            std::unique_ptr<TED_GenericResponse, TED_DestroyGenericFncPtr> response{
                TED_WriteMemoryFnc(m_client, writeAddress, &writeBytesMap[writeAddress], 1),
                TED_DestroyGenericFnc };
        }
    } else {
        ErrorMessageDialog::show("Address to write to is not valid");
    }
}

void MemoryWindow::on_pushButton_Read_clicked()
{
    this->ui->tableWidget_Bytes->setRowCount(0);

    m_previousByteValues.clear();

    bool validAddress{ };
    auto address{ this->ui->lineEdit_Address->text().toULongLong(&validAddress, 16) };
    if (validAddress) {
        std::unique_ptr<TED_ReadMemoryResponse, TED_DestroyReadMemoryFncPtr> response{
            TED_ReadMemoryFnc(m_client, address, 512), TED_DestroyReadMemoryFnc };
        if (response != nullptr) {
            QString hexBytes{ QByteArray::fromRawData(
                                  reinterpret_cast<const char *>(&response->bytes[0]),
                                  response->bytesCount).toHex(' ') };
            auto hexBytesSplit{ hexBytes.split(' ') };

            int i{ };
            int column{ };
            while (i < hexBytesSplit.size()) {
                int row{ i / (this->ui->tableWidget_Bytes->columnCount() - 1) };
                if (column == 0 || column == this->ui->tableWidget_Bytes->columnCount()) {
                    this->ui->tableWidget_Bytes->insertRow(this->ui->tableWidget_Bytes->rowCount());
                    auto newItem{ new QTableWidgetItem(QString::number(address, 16)) };
                    newItem->setFlags(newItem->flags() ^ Qt::ItemIsEditable);
                    this->ui->tableWidget_Bytes->setItem(row, 0, newItem);
                    address += (this->ui->tableWidget_Bytes->columnCount() - 1);
                    column   = 1;
                } else {
                    this->ui->tableWidget_Bytes->setItem(row, column,
                      new QTableWidgetItem(hexBytesSplit[i].toUpper()));
                    column++;
                    i++;
                }
            }
        } else {
            ErrorMessageDialog::show("Error reading memory");
        }
    } else {
        ErrorMessageDialog::show("Address to read from is not valid");
    }

    ui->tableWidget_Bytes->resizeColumnsToContents();
    ui->tableWidget_Bytes->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
}

void MemoryWindow::on_tableWidget_Bytes_itemChanged(QTableWidgetItem * item)
{
    ui->tableWidget_Bytes->blockSignals(true);

    auto selection{ this->ui->tableWidget_Bytes->selectedItems() };
    if (selection.size() > 0) {
        auto key{ QString::number(selection.at(0)->row(), 10) + QString{ "," }
                  + QString::number(selection.at(0)->column()) };
        auto currentByteValue{ selection.at(0)->text().toUpper() };
        if (m_previousByteValues[key] != currentByteValue) {
            item->setBackground(Qt::red);
        } else {
            item->setBackground(Qt::white);
        }

        item->setText(item->text().toUpper());
    }

    ui->tableWidget_Bytes->blockSignals(false);
}

void MemoryWindow::on_tableWidget_Bytes_itemSelectionChanged()
{
    auto selection{ this->ui->tableWidget_Bytes->selectedItems() };

    if (selection.size() > 0) {
        auto key{ QString::number(selection.at(0)->row(), 10) + QString{ "," }
                  + QString::number(selection.at(0)->column()) };
        if (!m_previousByteValues.contains(key)) {
            m_previousByteValues[key] = selection.at(0)->text().toUpper();
        }
    }
}
