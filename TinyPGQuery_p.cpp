#include "TinyPGQuery_p.h"

#include "TinyPGTemplates.h"
#include "TinyPGConnection_p.h"

#include <QtEndian>
#include <QCryptographicHash>
#include <QTimeZone>
#include <QDateTime>
#include <QUuid>
#include <QtGlobal>



namespace TinyPG
{

quint64 QueryPrivate::_stmt_number = 0;
QueryPrivate::QueryPrivate(std::weak_ptr<ConnectionPrivateThread> && db) : _db(db){}

QueryPrivate::~QueryPrivate()
{
    for(char * row : std::as_const(_dataRows)) delete[] row;
}

bool QueryPrivate::isLock() const
{
    return lock.load();
}

bool QueryPrivate::hasConnection() const
{
    return !_db.expired();
}

const QString & QueryPrivate::lastQuery() const
{
    return _lastQuery;
}

bool QueryPrivate::exec()
{
    if(lock.exchange(true)) return false;

    std::shared_ptr<ConnectionPrivateThread> db = _db.lock();

    if(!db)
    {
       lock.store(false);
       return false;
    }

    if(_prepare)
    {
       if(_prepareFinished) db->addQuery(this);
    }
    else if(!_lastQuery.isEmpty()) db->addQuery(this);

    return true;
}

bool QueryPrivate::exec(const QString & query)
{
    if(lock.exchange(true)) return false;

    std::shared_ptr<ConnectionPrivateThread> db = _db.lock();

    if(!db)
    {
       lock.store(false);
       return false;
    }

    _prepare = false;
    preparation(db, query);

    return true;
}

bool QueryPrivate::prepare(const QString & query)
{
    if(lock.exchange(true)) return false;

    std::shared_ptr<ConnectionPrivateThread> db = _db.lock();

    if(!db)
    {
       lock.store(false);
       return false;
    }

    _prepare = true;
    _stmt_number++;
    _stmtName = "stmt_" + QByteArray::number(_stmt_number);
    preparation(db, query);

    return true;
}

int QueryPrivate::preparedParameterCount() const
{
    if(lock.load()) return 0;

    return _preparedParameters.count();
}

QMetaType::Type QueryPrivate::preparedParameterType(int index) const
{
    if(lock.load()) return QMetaType::UnknownType;

    return (toVariants.size() < _preparedParameters[index]) ? QMetaType::UnknownType : toVariants.values[_preparedParameters[index]];
}

quint32 QueryPrivate::preparedParametrOid(int index) const
{
    if(lock.load()) return 0;

    return _preparedParameters[index];
}

int QueryPrivate::bindCount() const
{
    if(lock.load()) return 0;

    return _bindValues.size();
}

bool QueryPrivate::bindValue(int index, const std::variant<qint16, QVariant> & value)
{
    if(lock.load()) return false;

    if(index == _bindValues.size())
    {
       _bindValues.append(QVariant::fromStdVariant(value));

       return true;
    }
    else if(index < _bindValues.size())
    {
       _bindValues[index] = QVariant::fromStdVariant(value);

       return true;
    }

    return false;
}

QMetaType::Type QueryPrivate::bindedType(int index) const
{
    if(lock.load()) return QMetaType::UnknownType;

    return static_cast<QMetaType::Type>(_bindValues[index].userType());
}

const QVariant & QueryPrivate::bindedValue(int index) const
{
    static QVariant empty;

    if(lock.load()) return empty;

    return _bindValues[index];
}

int QueryPrivate::fieldCount() const
{
    if(lock.load()) return 0;

    return _fields.count();
}

const Field & QueryPrivate::field(int index) const
{
    static Field empty(FieldPrivate::makeEmpty());

    if(lock.load()) return empty;

    return _fields[index];
}

int QueryPrivate::rowCount() const
{
    if(lock.load()) return 0;

    return _dataRows.size();
}

int QueryPrivate::columnCount() const
{
    if(lock.load()) return 0;

    return _fields.count();
}

QVariant QueryPrivate::value(int row, int column) const
{
    constexpr auto types = GotoPointers<TypeMax()>(

        &&_BYTEA,

        {
            {BOOL, &&_BOOL},
            {INT2, &&_INT2},
            {INT4, &&_INT4},
            {INT8, &&_INT8},
            {FLOAT4, &&_FLOAT4},
            {FLOAT8, &&_FLOAT8},
            {DATE, &&_DATE},
            {TIME, &&_TIME},
            {TIMETZ, &&_TIMETZ},
            {TIMESTAMP, &&_TIMESTAMP},
            {BYTEA, &&_BYTEA},
            {TEXT, &&_TEXT},
            {UUID, &&_UUID}
        }
        );

    if(lock.load()) return QVariant();

    char * data = _dataRows[row];

    for(int i = 0; i <= _fields.count(); i++)
    {
        quint32 size = qFromBigEndian<quint32>(data);
        data += sizeof (quint32);

        if(i == column)
        {
            if(size == -1) return QVariant();

            if(types.size() < _fields[i].p->_typeOID) goto _BYTEA;
            else goto *types.pointers[_fields[i].p->_typeOID];

        _BOOL:
            return (data[0] == 0) ? false : true;

        _INT2:
            return QVariant::fromValue(qFromBigEndian<qint16>(data));

        _INT4:
            return qFromBigEndian<qint32>(data);

        _INT8:
            return qFromBigEndian<qint64>(data);

        _FLOAT4:
            return QVariant::fromValue(qFromBigEndian<float>(data));

        _FLOAT8:
            return qFromBigEndian<double>(data);

        _DATE:
            return QDate(2000, 1, 1).addDays(qFromBigEndian<qint32>(data));

        _TIME:
            return QTime::fromMSecsSinceStartOfDay(qFromBigEndian<qint64>(data)/1000);

        _TIMETZ:
            return QDateTime(QDate::fromJulianDay(0),
                             QTime::fromMSecsSinceStartOfDay(qFromBigEndian<qint64>(data)/1000),
                             QTimeZone(-qFromBigEndian<qint32>(data + sizeof (qint64))));

        _TIMESTAMP:
            return QDateTime::fromMSecsSinceEpoch(946674000000 + qFromBigEndian<qint64>(data)/1000);

        _BYTEA:
            return QByteArray(data, size);

        _TEXT:
            return QString(QLatin1String(data, size));

        _UUID:
            return QUuid::fromRfc4122(QByteArray(data, 16));
        }
        else if(size != -1) data += size;
    }

    return QVariant();
}

void QueryPrivate::preparation(std::shared_ptr<ConnectionPrivateThread> & db, const QString & query)
{
    _fields.clear();

    _preparedParameters.clear();
    _bindValues.clear();

    for(char * row : std::as_const(_dataRows)) delete[] row;
    _dataRows.clear();

    _lastQuery = query;
    _prepareFinished = false;
    db->addQuery(this);
}

void QueryPrivate::addPreparedParametr(quint32 oid)
{
    _preparedParameters.append(oid);
}

void QueryPrivate::addDataRow(const char * data, quint32 size)
{
    char * row = new char[size];
    std::memcpy(row, data, size);
    _dataRows.append(row);
}

QDebug operator << (QDebug debug, const QueryPrivate & query)
{
    QDebugStateSaver saver(debug);

    debug.nospace() << "Query(Query: " << query._lastQuery << ",\n";
    debug.nospace() << "      Prepare: " << query._prepare << ",\n";
    debug.nospace() << "      Prepare finished: " << query._prepareFinished << ",\n";
    debug.nospace() << "      Statement name: " << query._stmtName << ",\n";
    debug.nospace() << "      Fields count: " << query._fields.count() << ",\n";
    debug.nospace() << "      Prepared parametrs OID: ";

    bool first = false;

    for(const auto & v : query._preparedParameters)
    {
        if(!first)
        {
            debug.nospace() << v;
            first = true;
        }
        else
        {
            debug.nospace() << ", " << v;
        }
    }

    debug.nospace() << '\n';
    debug.nospace() << "      Number of binding values: " << query._bindValues.count() << ")";

    return debug;
}

}
