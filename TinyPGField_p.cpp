#include "TinyPGField_p.h"

#include <QDebug>

namespace TinyPG
{

bool FieldPrivate::operator==(const FieldPrivate & other)
{
    return (_name == other._name &&
            _tableOID == other._tableOID &&
            _columnIndex == other._columnIndex &&
            _typeOID == other._typeOID &&
            _typeSize == other._typeSize &&
            _typeModifier == other._typeModifier &&
            _formatType == other._formatType &&
            _type == other._type);
}

bool FieldPrivate::operator!=(const FieldPrivate & other)
{
    return !FieldPrivate::operator==(other);
}

FieldPrivate * FieldPrivate::makeEmpty()
{
    FieldPrivate * fp = new FieldPrivate;

    fp->_tableOID = 0;
    fp->_columnIndex = 0;
    fp->_typeOID = 0;
    fp->_typeSize = 0;
    fp->_typeModifier = 0;
    fp->_formatType = 0;
    fp->_type = QMetaType::UnknownType;

    return fp;
}

QDebug operator << (QDebug debug, const FieldPrivate & field)
{
    QDebugStateSaver saver(debug);

    debug.nospace() << "Field(Name: " << field._name << ",\n"
                    << "      Table ID: " << field._tableOID << ",\n"
                    << "      Column index: " << field._columnIndex << ",\n"
                    << "      Type ID: " << field._typeOID << ",\n"
                    << "      Type size: " << field._typeSize << ",\n"
                    << "      Type modifier: " << field._typeModifier << ",\n"
                    << "      Format type: " << field._formatType << ",\n"
                    << "      QMetaType type: " << field._type << ')';
    return debug;
}

}
