#include "TinyPG.h"

#include <QTcpSocket>
#include <QHostAddress>
#include <QtEndian>
#include <QCryptographicHash>
#include <QTimeZone>
#include <QDateTime>
#include <QUuid>
#include <QtGlobal>

namespace TinyPG
{

#if QT_VERSION >= 0x060000
#define vType typeId()
#else
#define vType type()
#endif

const QString & Message::importance() const
{
    return _importance;
}

const QString & Message::code() const
{
    return _code;
}

const QString & Message::message() const
{
    return _message;
}

QDebug operator << (QDebug debug, const Message &error)
{
    QDebugStateSaver saver(debug);

    debug.nospace() << "Message(Importance: " << error._importance << ",\n";
    debug.nospace() << "        Code: " << error._code << ",\n";
    debug.nospace() << "        Message: " << error._message << ")";

    return debug;
}

//Connection==============================================================================================
//========================================================================================================

#define _BOOLOID 16
#define _INT8OID 20
#define _INT2OID 21
#define _INT4OID 23
#define _FLOAT4OID 700
#define _FLOAT8OID 701
#define _DATEOID 1082
#define _TIMEOID 1083
#define _TIMETZOID 1266
#define _TIMESTAMPOID 1114
#define _TIMESTAMPTZOID 1184
#define _OIDOID 2278
#define _BYTEAOID 17
#define _REGPROCOID 24
#define _XIDOID 28
#define _CIDOID 29
#define _CHAROID 18
#define _VARCHAROID 1043
#define _TEXTOID 25
#define _UUIDOID 2950

#define NegotiateProtocolVersion 0x76
#define ErrorResponse 0x45
#define NoticeResponse 0x4e
#define AuthenticationRequest 0x52
#define AuthenticationSucces 0x00
#define PasswordMessage 0x70
#define ParameterStatus 0x53
#define BackendKeyData 0x4b
#define ReadyForQuery 0x5a
#define MD5password 0x05
#define Idle 0x49
#define Transaction 0x54
#define Exit 0x45
#define ErrorOrNoticeType 0x56
#define ErrorOrNoticeCode 0x43
#define ErrorOrNoticeMessage 0x4D
#define Parse 0x50
#define Bind 0x42
#define ParseComplite 0x31
#define BindCompletion 0x32
#define RowDescription 0x54
#define DataRow 0x44
#define NoData 0x6e
#define CommandCompletion 0x43
#define EmptyQueryResponse 0x49
#define Describe 0x44
#define Statement 0x53
#define ParameterDescription 0x74

static constexpr std::initializer_list<std::size_t> BOOL = {_BOOLOID};
static constexpr std::initializer_list<std::size_t> INT2 = {_INT2OID};
static constexpr std::initializer_list<std::size_t> INT4 = {_INT4OID, _OIDOID, _REGPROCOID, _XIDOID, _CIDOID};
static constexpr std::initializer_list<std::size_t> INT8 = {_INT8OID};
static constexpr std::initializer_list<std::size_t> FLOAT4 = {_FLOAT4OID};
static constexpr std::initializer_list<std::size_t> FLOAT8 = {_FLOAT8OID};
static constexpr std::initializer_list<std::size_t> DATE = {_DATEOID};
static constexpr std::initializer_list<std::size_t> TIME = {_TIMEOID};
static constexpr std::initializer_list<std::size_t> TIMETZ = {_TIMETZOID};
static constexpr std::initializer_list<std::size_t> TIMESTAMP = {_TIMESTAMPOID, _TIMESTAMPTZOID};
static constexpr std::initializer_list<std::size_t> BYTEA = {_BYTEAOID};
static constexpr std::initializer_list<std::size_t> TEXT = {_CHAROID, _VARCHAROID, _TEXTOID};
static constexpr std::initializer_list<std::size_t> UUID = {_UUIDOID};

static constexpr std::initializer_list<std::initializer_list<std::size_t>> TYPES = {
BOOL,INT2,INT4,INT8,FLOAT4,FLOAT8,DATE,TIME,TIMETZ,TIMESTAMP,BYTEA,TEXT,UUID
};

static constexpr std::size_t TypeMax()
{
    std::size_t max = 0;
    for(const auto & v : TYPES) max = std::max(max, *std::max_element(v.begin(), v.end()));
    return max;
}

template<typename T, std::size_t N = TypeMax()>struct VariantValues
{
    T values[N+1];

    template<typename F = T(*)(T)>constexpr VariantValues(std::initializer_list<std::tuple<std::initializer_list<std::size_t>, T>> list, F convert = nullptr):values()
    {
        for(const auto & v : list)
        {
            for(auto idx : std::get<0>(v))
            {
                if(convert == nullptr) values[idx] = std::get<1>(v);
                else values[idx] = convert(std::get<1>(v));
            }
        };
    }

    constexpr std::size_t size() const { return N; }
};

template<std::size_t N>struct GotoPointers
{
    void * pointers[N+1];

    constexpr GotoPointers(void * _default, std::initializer_list<std::tuple<std::size_t, void *>> list):pointers()
    {
        for(int i = 0; i < N+1; i++) pointers[i] = _default;

        for(const auto & v : list) pointers[std::get<0>(v)] = std::get<1>(v);
    }

    constexpr GotoPointers(void * _default, std::initializer_list<std::tuple<std::initializer_list<std::size_t>, void*>> list):pointers()
    {
        for(int i = 0; i < N+1; i++) pointers[i] = _default;

        for(const auto & v : list)
        {
            for(auto idx : std::get<0>(v))
            {
                pointers[idx] = std::get<1>(v);
            }
        };
    }

    constexpr std::size_t size() const { return N; }
};

//--------------------------------------------------------------------------------------------------------

#define TcpPacketSize 0xFFFF
#define MinimumPackageSize 0x05

Connection::Connection(QObject * parent) : QObject(parent)
{
    _bufferOut.reserve(TcpPacketSize);
    connect(&_socket, &QTcpSocket::connected, this, &Connection::makeStarupMessage);
    connect(&_socket, &QTcpSocket::readyRead, this, &Connection::analyzePacket);
    connect(&_socket, &QTcpSocket::disconnected, this, &Connection::close);
    connect(&_socket, &QAbstractSocket::errorOccurred, this, [this](QAbstractSocket::SocketError)
    {
        Message e;
        e._message = _socket.errorString();
        emit error(e);
    });
}

Connection::~Connection()
{
    close();
}

bool Connection::isConnect()
{
    return _auth_success;
}

void Connection::connection(const QHostAddress & address, quint16 port, const QString & user, const QString & password, const QString & database)
{
    close();

    _user = user.toUtf8();
    _password = password.toUtf8();
    _database = database.toUtf8();

    _socket.connectToHost(address, port);
}

void Connection::taskFromQueue()
{
    _bufferOut.truncate(0);
    Query * query = _tasks.head();

    if(query->_prepare)
    {
       if(query->_prepareFinished) runBindQuery(query); else runPrepareQuery(query);
    }
    else runQuery(query);
}

void Connection::endTask()
{
    if(_tasks.size() > 0)
    {
       Query * query = _tasks.dequeue();

       if(query->_prepare && query->_bindValues.isEmpty())
       {
          query->_prepareFinished = true;
          emit query->prepareFinished();
       }
       else emit query->executeFinished();

       if(_tasks.size() > 0) taskFromQueue();
    }
}

void Connection::addQuery(Query * query)
{
    _tasks.enqueue(query);
    if(_tasks.head() == query) taskFromQueue();
}

void Connection::runQuery(Query * query)
{
    const char BDES_msgs[] = {0x42, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x44,
                              0x00, 0x00, 0x00, 0x06, 0x50, 0x00, 0x45, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x53, 0x00, 0x00, 0x00, 0x04};

    constexpr quint32 sz = sizeof(quint32) + 4;
    QByteArray data = query->_lastQuery.toUtf8();
    quint32 size = sz + data.size();

    size = qToBigEndian(size);

    _bufferOut.append(Parse);
    _bufferOut.append(reinterpret_cast<char *>(&size), sizeof(quint32));
    _bufferOut.append(char(0));
    _bufferOut.append(data);
    _bufferOut.append(3, 0);

    _bufferOut.append(BDES_msgs, sizeof (BDES_msgs));
    _socket.write(_bufferOut);
}

void Connection::runPrepareQuery(Query * query)
{
    const unsigned char sync[] = {0x53, 0x00, 0x00, 0x00, 0x04};

    constexpr quint32 sz = sizeof(quint32) + 4;
    QByteArray data = query->_lastQuery.toUtf8();
    quint32 size = sz + query->_stmtName.size() + data.size();

    size = qToBigEndian(size);

    _bufferOut.append(Parse);
    _bufferOut.append(reinterpret_cast<char *>(&size), sizeof(quint32));
    _bufferOut.append(query->_stmtName);
    _bufferOut.append(char(0));
    _bufferOut.append(data);
    _bufferOut.append(3, 0);

    size = sizeof(quint32) + query->_stmtName.size() + 2;
    size = qToBigEndian(size);

    _bufferOut.append(char(Describe));
    _bufferOut.append(reinterpret_cast<char *>(&size), sizeof(quint32));
    _bufferOut.append(char(Statement));
    _bufferOut.append(query->_stmtName);
    _bufferOut.append(char(0));

    _bufferOut.append(reinterpret_cast<const char *>(&sync), sizeof(sync));
    _socket.write(_bufferOut);
}

void Connection::runBindQuery(Query * query)
{
    const char ES_msgs[] = {0x45, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53, 0x00, 0x00, 0x00, 0x04};
    const char bin_format[] = {0x00, 0x01, 0x00, 0x01};
    const char * const msg = "The binding does not support the type OID: ";

    constexpr auto types = GotoPointers<TypeMax()>(

      &&_default,

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

    constexpr auto sizes = VariantValues<quint32>(

      {
        {BOOL, sizeof(bool)},
        {INT2, sizeof(qint16)},
        {INT4, sizeof(qint32)},
        {INT8, sizeof(qint64)},
        {FLOAT4, sizeof(float)},
        {FLOAT8, sizeof(double)},
        {DATE, sizeof(qint32)},
        {TIME, sizeof(qint64)},
        {TIMETZ, 12},
        {TIMESTAMP, sizeof(qint64)},
        {BYTEA, 0},
        {TEXT, 0},
        {UUID, 16}
      },

      [](quint32 size){ return qToBigEndian(size); }

    );

    constexpr quint32 sz = sizeof(quint32) + 10;
    quint32 size = sz + query->_stmtName.size();

    _bufferOut.append(Bind);

    {
       quint32 sz = qToBigEndian(size);
       _bufferOut.append(reinterpret_cast<char *>(&sz), sizeof(quint32));
    }

    _bufferOut.append(char(0));
    _bufferOut.append(query->_stmtName);
    _bufferOut.append(char(0));

    quint16 values = query->_bindValues.size();

    if(values != query->_preparedParametrs.size())
    {
       Message e;
       e._message += tr("Incorrect value binding size: ") + QString::number(values) + " != " + QString::number(query->_preparedParametrs.size());
       emit query->error(e);
       return;
    }

    if(values > 0)
    {
       size += values * 2 + values * 4;
       values = qToBigEndian(values);
       _bufferOut.append(reinterpret_cast<char *>(&values), sizeof(quint16));

       quint16 type = qToBigEndian(quint16(1));
       for(int i = 0; i < query->_bindValues.size(); i++) _bufferOut.append(reinterpret_cast<char *>(&type), sizeof(quint16));
       _bufferOut.append(reinterpret_cast<char *>(&values), sizeof(quint16));

       for(int i = 0; i < query->_bindValues.size(); i++)
       {   
           quint32 oid = query->_preparedParametrs[i];

           if(types.size() < oid)
           {
              Message e;
              e._message += tr(msg) + QString::number(oid);
              emit query->error(e);
              return;
           }

           const QVariant & value = query->_bindValues[i];

           if(oid <= types.size()) goto *types.pointers[oid];
           else goto _default;

           _BOOL:
           {
             size += sizeof(bool);

             bool v = value.toBool();
             _bufferOut.append(reinterpret_cast<const char *>(&sizes.values[oid]), sizeof(quint32));
             _bufferOut.append(reinterpret_cast<char *>(&v), sizeof(bool));
           }
           continue;

           _INT2:
           {
             size += sizeof(qint16);

             qint16 v = qToBigEndian(qint16(value.toInt()));
             _bufferOut.append(reinterpret_cast<const char *>(&sizes.values[oid]), sizeof(quint32));
             _bufferOut.append(reinterpret_cast<char *>(&v), sizeof(qint16));
           }
           continue;

           _INT4:
           {
             size += sizeof(qint32);

             qint32 v = qToBigEndian(value.toInt());
             _bufferOut.append(reinterpret_cast<const char *>(&sizes.values[oid]), sizeof(quint32));
             _bufferOut.append(reinterpret_cast<char *>(&v), sizeof(qint32));
           }
           continue;

           _INT8:
           {
             size += sizeof(qint64);

             qint64 v = qToBigEndian(value.toLongLong());
             _bufferOut.append(reinterpret_cast<const char *>(&sizes.values[oid]), sizeof(quint32));
             _bufferOut.append(reinterpret_cast<char *>(&v), sizeof(qint64));
           }
           continue;

           _FLOAT4:
           {
             size += sizeof(float);

             float v = qToBigEndian(value.toFloat());
             _bufferOut.append(reinterpret_cast<const char *>(&sizes.values[oid]), sizeof(quint32));
             _bufferOut.append(reinterpret_cast<char *>(&v), sizeof(float));
           }
           continue;

           _FLOAT8:
           {
             size += sizeof(double);

             double v = qToBigEndian(value.toDouble());
             _bufferOut.append(reinterpret_cast<const char *>(&sizes.values[oid]), sizeof(quint32));
             _bufferOut.append(reinterpret_cast<char *>(&v), sizeof(double));
           }
           continue;

           _DATE:
           {
             size += sizeof(qint32);

             qint32 v = qToBigEndian(qint32(QDate(2000, 1, 1).daysTo(value.toDate())));
             _bufferOut.append(reinterpret_cast<const char *>(&sizes.values[oid]), sizeof(quint32));
             _bufferOut.append(reinterpret_cast<char *>(&v), sizeof(qint32));
           }
           continue;

           _TIME:
           {
             size += sizeof(qint64);

             qint64 v = qToBigEndian(qint64(value.toTime().msecsSinceStartOfDay())*1000);
             _bufferOut.append(reinterpret_cast<const char *>(&sizes.values[oid]), sizeof(quint32));
             _bufferOut.append(reinterpret_cast<char *>(&v), sizeof(qint64));
           }
           continue;

           _TIMETZ:
           {
             size += 12;

             QDateTime dt = value.toDateTime();
             qint64 t =qToBigEndian(qint64(dt.time().msecsSinceStartOfDay())*1000);
             qint32 tz = qFromBigEndian<qint32>(-dt.timeZone().offsetFromUtc(dt));
             _bufferOut.append(reinterpret_cast<const char *>(&sizes.values[oid]), sizeof(quint32));
             _bufferOut.append(reinterpret_cast<char *>(&t), sizeof(qint64));
             _bufferOut.append(reinterpret_cast<char *>(&tz), sizeof(qint32));
           }
           continue;

           _TIMESTAMP:
           {
             size += sizeof(qint64);

             qint64 v = qToBigEndian((value.toDateTime().toMSecsSinceEpoch() - 946674000000)*1000);
             _bufferOut.append(reinterpret_cast<const char *>(&sizes.values[oid]), sizeof(quint32));
             _bufferOut.append(reinterpret_cast<char *>(&v), sizeof(qint64));
           }
           continue;

           _BYTEA:
           {
             QByteArray data = value.toByteArray();
             quint32 sz = data.size();
             size += sz;
             sz = qToBigEndian(sz);

             _bufferOut.append(reinterpret_cast<char *>(&sz), sizeof(quint32));
             _bufferOut.append(data.data(), data.size());
           }
           continue;

           _TEXT:
           {
             QByteArray data = value.toByteArray();
             quint32 sz = data.size();
             size += sz;
             sz = qToBigEndian(sz);

             _bufferOut.append(reinterpret_cast<char *>(&sz), sizeof(quint32));
             _bufferOut.append(data.data(), data.size());
           }
           continue;

           _UUID:
           {
             size += 16;

             _bufferOut.append(reinterpret_cast<const char *>(&sizes.values[oid]), sizeof(quint32));
             _bufferOut.append(value.toUuid().toRfc4122().data(), 16);
           }
           continue;

           _default:

           Message e;
           e._message += tr(msg) + QString::number(oid);
           emit query->error(e);
           return;
       }

       size = qToBigEndian(size);
       _bufferOut.replace(1, sizeof(quint32), reinterpret_cast<char *>(&size), sizeof(quint32));
    }
    else
    {
       _bufferOut.append(4, 0);
    }

    _bufferOut.append(bin_format, sizeof(bin_format));
    _bufferOut.append(ES_msgs, sizeof (ES_msgs));
    _socket.write(_bufferOut);
}

void Connection::close()
{
    const unsigned char Termination[] = {0x58, 0x00, 0x00, 0x00, 0x04};

    _pid = 0;
    _key = 0;

    if(_socket.state() == QAbstractSocket::ConnectedState)
    {
       if(_auth_success)
       {
          emit disconnected();
          _socket.write(reinterpret_cast<const char *>(Termination), sizeof (Termination));
          _socket.waitForBytesWritten();
       }
       _socket.close();
    }
}

void Connection::errorOrNoticeResponse(const char * data, quint32 size, ErrorOrNotice type)
{
    quint32 pos = 0;
    QLatin1String v, c, m;

    do
    {
       char type = *(data + pos);

       pos++;
       QLatin1String temp(data + pos);
       pos += temp.size();
       pos++;

       switch (type)
       {
               case ErrorOrNoticeType: v = temp;
               break;
               case ErrorOrNoticeCode: c = temp;
               break;
               case ErrorOrNoticeMessage: m = temp;
               break;
       }
    }
    while(pos < size || (v.size() == 0 || c.size() == 0 || m.size() == 0));

    if(type == ErrorOrNotice::Error)
    {
       Message e;
       e._importance = v;
       e._code = c;
       e._message = m;

       if(_tasks.size() > 0) emit _tasks.head()->error(e);
       else emit error(e);
    }
    else
    {
       Message n;
       n._importance = v;
       n._code = c;
       n._message = m;

       if(_tasks.size() > 0) emit _tasks.head()->notice(n);
       else emit notice(n);
    }
}

bool Connection::authentication(const char * data)
{
    quint32 type = qFromBigEndian<quint32>(data);

    if(type == MD5password)
    {
       QByteArray hash = "md5" + QCryptographicHash::hash(
                                  QCryptographicHash::hash(_password+_user,
                                   QCryptographicHash::Md5).toHex() + QByteArray(data + 4, 4),
                                    QCryptographicHash::Md5).toHex();

       _bufferOut.append(PasswordMessage);

       quint32 size = sizeof(quint32) + hash.size();
       size++;

       size = qToBigEndian(size);

       _bufferOut.append(reinterpret_cast<char *>(&size), sizeof (size));
       _bufferOut.append(hash);
       _bufferOut.append(char(0));

       _socket.write(_bufferOut);
       _bufferOut.truncate(0);

       return true;
    }
    else if(type == AuthenticationSucces)
    {
       _auth_success = true;
       emit connected();
       return true;
    }

    return false;
}

void Connection::parameterStatus(const char * data)
{
    QLatin1String key(data);
    data++;
    _parametersStatus[key] = QLatin1String(data + key.size());
}

void Connection::backendKeyData(const char * data)
{
    _pid = qFromBigEndian<quint32>(data);
    _key = qFromBigEndian<quint32>(data + sizeof (quint32));
}

void Connection::readyForQuery(const char * data)
{
    switch(char(*data))
    {
        case Idle: endTask();
        break;
        case Transaction: endTask();
        break;
        case Exit:
        break;
    }
}

void Connection::rowDescription(const char * data)
{
    constexpr auto toVariants = VariantValues<QMetaType::Type>(
    {
       {BOOL,QMetaType::Bool},
       {INT2,QMetaType::Short},
       {INT4,QMetaType::Int},
       {INT8,QMetaType::LongLong},
       {FLOAT4,QMetaType::Float},
       {FLOAT8,QMetaType::Double},
       {DATE,QMetaType::QDate},
       {TIME,QMetaType::QTime},
       {TIMETZ,QMetaType::QDateTime},
       {TIMESTAMP,QMetaType::QDateTime},
       {BYTEA,QMetaType::QByteArray},
       {TEXT,QMetaType::QString},
       {UUID,QMetaType::QUuid}
    });

    Query * query = _tasks.head();
    quint16 fieldCount = qFromBigEndian<quint16>(data), i = 0;

    for(quint32 pos = sizeof (quint16); i < fieldCount; i++)
    {
        Field field;
        QLatin1String name(data + pos);
        field._name = name;

        pos += name.size();
        pos++;

        field._tableOID = qFromBigEndian<quint32>(data + pos);
        pos += sizeof (quint32);
        field._columnIndex = qFromBigEndian<quint16>(data + pos);
        pos += sizeof (quint16);
        field._typeOID = qFromBigEndian<quint32>(data + pos);

        if(toVariants.size() < field._typeOID) field._type = QMetaType::UnknownType;
        else field._type = toVariants.values[field._typeOID];

        pos += sizeof (quint32);
        field._typeSize = qFromBigEndian<qint16>(data + pos);
        pos += sizeof (qint16);
        field._typeModifier = qFromBigEndian<qint32>(data + pos);
        pos += sizeof (qint32);
        field._formatType = qFromBigEndian<quint16>(data + pos);
        pos += sizeof (quint16);

        query->_fields.append(std::move(field));
    }
}

void Connection::preparedParametrs(const char * data, quint32 size)
{
    for(int i = 0; i < qFromBigEndian<quint16>(data); i++) _tasks.head()->addPreparedParametr(qFromBigEndian<quint32>(data + sizeof(quint16) + i * sizeof(quint32)));
}

void Connection::dataRow(const char * data, quint32 size)
{
    _tasks.head()->addDataRow(data + sizeof (quint16), size - sizeof (quint16));
}

void Connection::makeStarupMessage()
{
    const quint16 ProtocolVersion[] = {qToBigEndian(quint16(0x03)), 0x00};
    const char user[] = "user", database[] = "database";

    constexpr int sz = sizeof (quint32) + sizeof (ProtocolVersion) + sizeof (user) + 2;
    quint32 size = sz + _user.size();

    if(_database.size() > 0)
    {
       size += sizeof (database) + _database.size();
       size++;
    }

    size = qToBigEndian(size);
    _bufferOut.append(reinterpret_cast<char *>(&size), sizeof (size));
    _bufferOut.append(reinterpret_cast<const char *>(&ProtocolVersion), sizeof (ProtocolVersion));
    _bufferOut.append(user, sizeof (user));
    _bufferOut.append(_user);
    _bufferOut.append(char(0));

    if(_database.size() > 0)
    {
       _bufferOut.append(database, sizeof (database));
       _bufferOut.append(_database);
       _bufferOut.append(char(0));
    }

    _bufferOut.append(char(0));
    _socket.write(_bufferOut);
    _bufferOut.truncate(0);
}

void Connection::analyzePacket()
{
    constexpr auto proto = GotoPointers<std::numeric_limits<quint8>::max()>(

      &&_default,

      {
        {DataRow, &&_DataRow},
        {NoData, &&_next},
        {ParameterDescription, &&_ParameterDescription},
        {RowDescription, &&_RowDescription},
        {ReadyForQuery, &&_ReadyForQuery},
        {CommandCompletion, &&_CommandCompletion},
        {EmptyQueryResponse, &&_next},
        {ParseComplite, &&_next},
        {BindCompletion, &&_next},
        {ErrorResponse, &&_ErrorResponse},
        {NoticeResponse, &&_NoticeResponse},
        {ParameterStatus, &&_ParameterStatus},
        {AuthenticationRequest, &&_AuthenticationRequest},
        {BackendKeyData, &&_BackendKeyData},
        {NegotiateProtocolVersion, &&_NegotiateProtocolVersion},
      }
    );

    bool complete = false;

    quint32 pos = 0;
    QByteArray data = _bufferIn + _socket.readAll();
    _bufferIn.clear();

    if(data.size() < MinimumPackageSize)
    {
       Message e;
       e._message = tr("Minimum data packet size error");
       emit error(e);
       close();
       return;
    }

    do
    {
       quint32 size = qFromBigEndian<quint32>(data.data() + pos + 1);

       if(static_cast<quint32>(data.size()) <= pos + size)
       {
          if(complete)
          {
             Message e;
             e._message = tr("Protocol message size error");
             emit error(e);
             close();
             return;
          }

          _bufferIn = data.mid(pos);
          return;
       }

       goto *proto.pointers[data[pos]];

       _DataRow: dataRow(data.data() + pos + MinimumPackageSize, size - sizeof (quint32));
        goto _next;

       _ParameterDescription: preparedParametrs(data.data() + pos + MinimumPackageSize, size - sizeof (quint32));
        goto _next;

       _RowDescription: rowDescription(data.data() + pos + MinimumPackageSize);
        goto _next;

       _ReadyForQuery: readyForQuery(data.data() + pos + MinimumPackageSize);
        goto _next;

       _CommandCompletion: complete = true;
        goto _next;

       _ErrorResponse: errorOrNoticeResponse(data.data() + pos + MinimumPackageSize, size - sizeof (quint32), ErrorOrNotice::Error);
        goto _next;

       _NoticeResponse: errorOrNoticeResponse(data.data() + pos + MinimumPackageSize, size - sizeof (quint32), ErrorOrNotice::Notice);
        goto _next;

       _ParameterStatus: parameterStatus(data.data() + pos + MinimumPackageSize);
        goto _next;

       _AuthenticationRequest:

        if(!authentication(data.data() + pos + MinimumPackageSize))
        {
           Message e;
           e._message = tr("Authorization error");
           emit error(e);
           close();
           return;
        }

        goto _next;

       _BackendKeyData : backendKeyData(data.data() + pos + MinimumPackageSize);
        goto _next;

       _NegotiateProtocolVersion :
        {
          Message e;
          e._message = tr("Protocol version 3.0 is not supported");
          emit error(e);
          close();
          return;
        }

        _default:
        {
          Message e;
          e._message = tr("Does not support the type of message in the protocol: ") + data[pos];
          emit error(e);
          close();
          return;
        }

       _next:
       pos += size;
       pos++;
    }
    while(pos + MinimumPackageSize <= static_cast<quint32>(data.size()));

    if(pos != static_cast<quint32>(data.size()))
    {
       if(complete)
       {
          Message e;
          e._message = tr("Data segmentation error");
          emit error(e);
          close();
       }

       _bufferIn = data.mid(pos);
       return;
    }
}

//Query===================================================================================================
//========================================================================================================

quint64 Query::_stmt_number = 0;
Query::Query(Connection * db, QObject * parent) : QObject(parent), _db(db){}

Query::~Query()
{
    for(char * row : std::as_const(_dataRows)) delete[] row;
}

const QString & Query::lastQuery() const
{
    return _lastQuery;
}

void Query::exec()
{
    if(_db == nullptr) return;

    if(_prepare)
    {
        if(_prepareFinished) _db->addQuery(this);
    }
    else if(!_lastQuery.isEmpty()) _db->addQuery(this);
}

void Query::exec(const QString & query)
{
    if(_db == nullptr) return;
    _prepare = false;
    preparation(query);
}

void Query::prepare(const QString & query)
{
    if(_db == nullptr) return;
    _prepare = true;
    _stmt_number++;
    _stmtName = "stmt_" + QByteArray::number(_stmt_number);
    preparation(query);
}

const QVector<QVariant> & Query::bindValues() const
{
    return _bindValues;
}

void Query::bindValue(int index, const std::variant<qint16, qint32, QVariant> & value)
{
    if(_db == nullptr || !_prepareFinished) return;
    _bindValues.insert(index, QVariant::fromStdVariant(value));
}

const QVector<Field> & Query::fields() const
{
    return _fields;
}

int Query::rowCount() const
{
    return _dataRows.size();
}

int Query::columnCount() const
{
    return _fields.size();
}

QVariant Query::value(int row, int column) const
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

    char * data = _dataRows[row];

    for(int i = 0; i <= _fields.count(); i++)
    {
        quint32 size = qFromBigEndian<quint32>(data);
        data += sizeof (quint32);

        if(i == column)
        {
           if(size == -1) return QVariant();

           if(types.size() < _fields[i]._typeOID) goto _BYTEA;
           else goto *types.pointers[_fields[i]._typeOID];

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

void Query::preparation(const QString & query)
{
    _fields.clear();
    _preparedParametrs.clear();
    _bindValues.clear();

    for(char * row : std::as_const(_dataRows)) delete[] row;
    _dataRows.clear();

    _lastQuery = query;
    _prepareFinished = false;
    _db->addQuery(this);
}

void Query::addPreparedParametr(quint32 oid)
{
    _preparedParametrs.append(oid);
}

void Query::addDataRow(const char * data, quint32 size)
{
    char * row = new char[size];
    std::memcpy(row, data, size);
    _dataRows.append(row);
}

QDebug operator << (QDebug debug, const Query & query)
{
    QDebugStateSaver saver(debug);

    debug.nospace() << "Query(Query: " << query._lastQuery << ",\n";
    debug.nospace() << "      Prepare: " << query._prepare << ",\n";
    debug.nospace() << "      Prepare finished: " << query._prepareFinished << ",\n";
    debug.nospace() << "      Statement name: " << query._stmtName << ",\n";
    debug.nospace() << "      Fields count: " << query._fields.count() << ",\n";
    debug.nospace() << "      Prepared parametrs OID: ";

    bool first = false;

    for(const auto & v : query._preparedParametrs)
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

//Field===================================================================================================
//========================================================================================================

Field::Field(){}

const QString & Field::name() const
{
    return _name;
}

quint32 Field::tableOID() const
{
    return _tableOID;
}

quint16 Field::columnIndex() const
{
    return _columnIndex;
}

quint32 Field::typeOID() const
{
    return _typeOID;
}

qint16 Field::typeSize() const
{
    return _typeSize;
}

qint32 Field::typeModifier() const
{
    return _typeModifier;
}

quint16 Field::formatType() const
{
    return _formatType;
}

QMetaType::Type Field::type() const
{
    return _type;
}

QDebug operator << (QDebug debug, const Field & field)
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
