#ifndef TINYPGFIELDPRIVATE_H
#define TINYPGFIELDPRIVATE_H

#include <QString>
#include <QMetaType>


namespace TinyPG
{

class FieldPrivate final
{
    friend class Field;
    friend class ConnectionPrivateThread;
    friend class QueryPrivate;
    friend QDebug operator << (QDebug debug, const FieldPrivate & field);

    bool operator==(const FieldPrivate & other);
    bool operator!=(const FieldPrivate & other);

    std::atomic_uint64_t counter = 1;

    QString _name;
    quint32 _tableOID;
    quint16 _columnIndex;
    quint32 _typeOID;
    qint16 _typeSize;
    qint32 _typeModifier;
    quint16 _formatType;
    QMetaType::Type _type;

    static FieldPrivate * makeEmpty();
};

QDebug operator << (QDebug debug, const FieldPrivate & field);

}

#endif // TINYPGFIELDPRIVATE_H
