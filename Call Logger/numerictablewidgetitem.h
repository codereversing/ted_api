#ifndef NUMERICTABLEWIDGETITEM_H
#define NUMERICTABLEWIDGETITEM_H

#include <QTableWidgetItem>

class NumericTableWidgetItem : public QTableWidgetItem
{
public:
    NumericTableWidgetItem(const QString text, int base = 10)
        : QTableWidgetItem(text)
        , m_base{base}
    { }

    bool operator < (const QTableWidgetItem &other) const
    {
        bool ok{ };

        return text().toULongLong(&ok, m_base) < other.text().toULongLong(&ok, m_base);
    }

private:
    int m_base;
};

#endif // NUMERICTABLEWIDGETITEM_H
