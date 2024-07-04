#include "TinyPGConnection_p.h"

#include "TinyPGTemplates.h"
#include "TinyPGMessage_p.h"
#include "TinyPGQuery_p.h"

#include <QtEndian>
#include <QCryptographicHash>
#include <QTimeZone>
#include <QDateTime>
#include <QUuid>
#include <QtGlobal>

namespace TinyPG
{

#define TcpPacketSize 0xFFFF
#define MinimumPackageSize 0x05

ConnectionPrivateThread::ConnectionPrivateThread() : _socket(*this)
{
    _bufferOut.reserve(TcpPacketSize);
}

ConnectionPrivateThread::~ConnectionPrivateThread()
{
    closeConnection();
}

void ConnectionPrivateThread::connection(const QString & host, quint16 port, const QString & user, const QString & password, const QString & database)
{
    if(_socket.isConnected()) return;

    _user = user.toUtf8();
    _password = password.toUtf8();
    _database = database.toUtf8();

    _state.store(true);
    _socket.connectToHost(host, port);
}

void ConnectionPrivateThread::taskFromQueue()
{
    _bufferOut.truncate(0);
    QueryPrivate * query = _tasks.head();

    if(query->_prepare)
    {
       if(query->_prepareFinished) runBindQuery(query); else runPrepareQuery(query);
    }
    else runQuery(query);
}

void ConnectionPrivateThread::endTask()
{
    std::lock_guard<std::mutex>lock(mutex);

    if(_tasks.size() > 0)
    {
       QueryPrivate * query = _tasks.dequeue();

       query->counter--;

       if(query->counter.load() == 0)
       {
          delete query;
       }
       else
       {
          query->lock.store(false);

          if(query->_prepare && query->_bindValues.isEmpty())
          {
             query->_prepareFinished = true;
             emit query->prepareFinished();
          }
          else emit query->executeFinished();
       }

       if(_tasks.size() > 0) taskFromQueue();
    }
}

void ConnectionPrivateThread::addQuery(QueryPrivate * query)
{
    if(!_state.load()) return;

    query->counter++;

    std::lock_guard<std::mutex>lock(mutex);

    _tasks.enqueue(query);

    if(_tasks.head() == query) taskFromQueue();
}

void ConnectionPrivateThread::runQuery(QueryPrivate * query)
{
    const char BDES_msgs[] = {0x42, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x44,
                              0x00, 0x00, 0x00, 0x06, 0x50, 0x00, 0x45, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x53, 0x00, 0x00, 0x00, 0x04};

    constexpr quint32 sz = sizeof(quint32) + 4;
    QByteArray data = query->_lastQuery.toUtf8();
    quint32 size = sz + data.size();

    size = qToBigEndian(size);

    _bufferOut.append(PG_Parse);
    _bufferOut.append(reinterpret_cast<char *>(&size), sizeof(quint32));
    _bufferOut.append(char(0));
    _bufferOut.append(data);
    _bufferOut.append(3, 0);

    _bufferOut.append(BDES_msgs, sizeof (BDES_msgs));
    _socket.write(_bufferOut);
}

void ConnectionPrivateThread::runPrepareQuery(QueryPrivate * query)
{
    const unsigned char sync[] = {0x53, 0x00, 0x00, 0x00, 0x04};

    constexpr quint32 sz = sizeof(quint32) + 4;
    QByteArray data = query->_lastQuery.toUtf8();
    quint32 size = sz + query->_stmtName.size() + data.size();

    size = qToBigEndian(size);

    _bufferOut.append(PG_Parse);
    _bufferOut.append(reinterpret_cast<char *>(&size), sizeof(quint32));
    _bufferOut.append(query->_stmtName);
    _bufferOut.append(char(0));
    _bufferOut.append(data);
    _bufferOut.append(3, 0);

    size = sizeof(quint32) + query->_stmtName.size() + 2;
    size = qToBigEndian(size);

    _bufferOut.append(char(PG_Describe));
    _bufferOut.append(reinterpret_cast<char *>(&size), sizeof(quint32));
    _bufferOut.append(char(PG_Statement));
    _bufferOut.append(query->_stmtName);
    _bufferOut.append(char(0));

    _bufferOut.append(reinterpret_cast<const char *>(&sync), sizeof(sync));
    _socket.write(_bufferOut);
}

void ConnectionPrivateThread::runBindQuery(QueryPrivate * query)
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

    _bufferOut.append(PG_Bind);

    {
        quint32 sz = qToBigEndian(size);
        _bufferOut.append(reinterpret_cast<char *>(&sz), sizeof(quint32));
    }

    _bufferOut.append(char(0));
    _bufferOut.append(query->_stmtName);
    _bufferOut.append(char(0));

    quint16 values = query->_bindValues.size();

    if(values != query->_preparedParameters.size())
    {
        MessagePrivate * e = new MessagePrivate;
        e->_message += tr("Incorrect value binding size: ") + QString::number(values) + " != " + QString::number(query->_preparedParameters.size());
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
            quint32 oid = query->_preparedParameters[i];

            if(types.size() < oid)
            {
                MessagePrivate * e = new MessagePrivate;
                e->_message += tr(msg) + QString::number(oid);
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

            MessagePrivate * e = new MessagePrivate;
            e->_message += tr(msg) + QString::number(oid);
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

void ConnectionPrivateThread::closeConnection()
{
    const unsigned char Termination[] = {0x58, 0x00, 0x00, 0x00, 0x04};

    _pid = 0;
    _key = 0;

    if(_socket.isConnected())
    {
        if(_auth_success)
        {
           _socket.write(QByteArray(reinterpret_cast<const char *>(Termination), sizeof (Termination)));
           _socket.close();

           emit disconnected();
        }
        else
        {
           _socket.close();
        }
    }

    _state.store(false);

    std::lock_guard<std::mutex>lock(mutex);

    for(int i = 0; i < _tasks.size(); i++)
    {
        QueryPrivate * query = _tasks.dequeue();

        query->counter--;

        if(query->counter.load() == 0)
        {
           delete query;
           continue;
        }

        emit query->notDone();
    }
}

void ConnectionPrivateThread::errorOrNoticeResponse(const char * data, quint32 size, ErrorOrNotice type)
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
        case PG_ErrorOrNoticeType: v = temp;
            break;
        case PG_ErrorOrNoticeCode: c = temp;
            break;
        case PG_ErrorOrNoticeMessage: m = temp;
            break;
        }
    }
    while(pos < size || (v.size() == 0 || c.size() == 0 || m.size() == 0));

    if(type == ErrorOrNotice::Error)
    {
        MessagePrivate * e = new MessagePrivate;
        e->_importance = v;
        e->_code = c;
        e->_message = m;

        if(_tasks.size() > 0) emit _tasks.head()->error(e);
        else emit error(e);
    }
    else
    {
        MessagePrivate * n = new MessagePrivate;
        n->_importance = v;
        n->_code = c;
        n->_message = m;

        if(_tasks.size() > 0) emit _tasks.head()->notice(n);
        else emit notice(n);
    }
}

bool ConnectionPrivateThread::authentication(const char * data, quint32 size)
{
    quint32 type = qFromBigEndian<quint32>(data);

    if(type == PG_MD5password)
    {
        QByteArray hash = "md5" + QCryptographicHash::hash(
                                      QCryptographicHash::hash(_password+_user,
                                                               QCryptographicHash::Md5).toHex() + QByteArray(data + 4, 4),
                                      QCryptographicHash::Md5).toHex();

        _bufferOut.append(PG_PasswordMessage);

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
    else if(type == PG_SASL)
    {
        if(QLatin1String(data + sizeof(quint32)) == "SCRAM-SHA-256")
        {
           const char SASLInitialResponse[] = {0x70,
                                               0x00, 0x00, 0x00, 0x36,
                                               0x53, 0x43, 0x52, 0x41, 0x4d, 0x2d, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x00,
                                               0x00, 0x00, 0x00, 0x20};

           if(scram == nullptr) scram = new SCRAM_SHA256(this);

           _bufferOut.append(SASLInitialResponse, sizeof(SASLInitialResponse));
           _bufferOut.append(scram->initialResponse());

           _socket.write(_bufferOut);
           _bufferOut.truncate(0);

           return true;
        }
    }
    else if(type == PG_SASL_Continue)
    {
        const char SASLResponseMessage[] = {0x70,
                                            0x00, 0x00, 0x00, 0x6c};

        if(scram == nullptr) return false;

        constexpr size_t offset = sizeof(quint32)*2;
        QByteArray final = scram->finalResponse(_password,QByteArray(data + sizeof(quint32), size - offset));

        _bufferOut.append(SASLResponseMessage, sizeof(SASLResponseMessage));
        _bufferOut.append(final);

        _socket.write(_bufferOut);
        _bufferOut.truncate(0);

        return true;
    }
    else if(type == PG_SASL_Complete)
    {
        return true;
    }
    else if(type == PG_AuthenticationSucces)
    {
        _auth_success = true;
        emit connected();
        return true;
    }

    return false;
}

void ConnectionPrivateThread::parameterStatus(const char * data)
{
    QLatin1String key(data);
    data++;
    _parametersStatus[key] = QLatin1String(data + key.size());
}

void ConnectionPrivateThread::backendKeyData(const char * data)
{
    _pid = qFromBigEndian<quint32>(data);
    _key = qFromBigEndian<quint32>(data + sizeof (quint32));
}

void ConnectionPrivateThread::readyForQuery(const char * data)
{
    switch(char(*data))
    {
    case PG_Idle: endTask();
        break;
    case PG_Transaction: endTask();
        break;
    case PG_Exit:
        break;
    }
}

void ConnectionPrivateThread::rowDescription(const char * data)
{
    QueryPrivate * query = _tasks.head();
    quint16 fieldCount = qFromBigEndian<quint16>(data), i = 0;

    for(quint32 pos = sizeof (quint16); i < fieldCount; i++)
    {
        FieldPrivate * field = new FieldPrivate;
        QLatin1String name(data + pos);
        field->_name = name;

        pos += name.size();
        pos++;

        field->_tableOID = qFromBigEndian<quint32>(data + pos);
        pos += sizeof (quint32);
        field->_columnIndex = qFromBigEndian<quint16>(data + pos);
        pos += sizeof (quint16);
        field->_typeOID = qFromBigEndian<quint32>(data + pos);

        if(toVariants.size() < field->_typeOID) field->_type = QMetaType::UnknownType;
        else field->_type = toVariants.values[field->_typeOID];

        pos += sizeof (quint32);
        field->_typeSize = qFromBigEndian<qint16>(data + pos);
        pos += sizeof (qint16);
        field->_typeModifier = qFromBigEndian<qint32>(data + pos);
        pos += sizeof (qint32);
        field->_formatType = qFromBigEndian<quint16>(data + pos);
        pos += sizeof (quint16);

        query->_fields.append(field);
    }
}

void ConnectionPrivateThread::preparedParametrs(const char * data, quint32 size)
{
    for(int i = 0; i < qFromBigEndian<quint16>(data); i++) _tasks.head()->addPreparedParametr(qFromBigEndian<quint32>(data + sizeof(quint16) + i * sizeof(quint32)));
}

void ConnectionPrivateThread::dataRow(const char * data, quint32 size)
{
    _tasks.head()->addDataRow(data + sizeof (quint16), size - sizeof (quint16));
}

void ConnectionPrivateThread::sockConnected()
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

void ConnectionPrivateThread::sockReadyRead()
{
    constexpr auto proto = GotoPointers<std::numeric_limits<quint8>::max()>(

        &&_default,

        {
         {PG_DataRow, &&_DataRow},
         {PG_NoData, &&_next},
         {PG_ParameterDescription, &&_ParameterDescription},
         {PG_RowDescription, &&_RowDescription},
         {PG_ReadyForQuery, &&_ReadyForQuery},
         {PG_CommandCompletion, &&_CommandCompletion},
         {PG_EmptyQueryResponse, &&_next},
         {PG_ParseComplite, &&_next},
         {PG_BindCompletion, &&_next},
         {PG_ErrorResponse, &&_ErrorResponse},
         {PG_NoticeResponse, &&_NoticeResponse},
         {PG_ParameterStatus, &&_ParameterStatus},
         {PG_AuthenticationRequest, &&_AuthenticationRequest},
         {PG_BackendKeyData, &&_BackendKeyData},
         {PG_NegotiateProtocolVersion, &&_NegotiateProtocolVersion},
         }
        );

    bool complete = false;

    quint32 pos = 0;

    char r_data[TcpPacketSize];
    QByteArray data = _bufferIn + QByteArray(r_data, _socket.read(r_data, sizeof(r_data)));
    _bufferIn.clear();

    if(data.size() < MinimumPackageSize)
    {
        MessagePrivate * e = new MessagePrivate;
        e->_message = tr("Minimum data packet size error");
        emit error(e);
        closeConnection();
        return;
    }

    do
    {
        quint32 size = qFromBigEndian<quint32>(data.data() + pos + 1);

        if(static_cast<quint32>(data.size()) <= pos + size)
        {
            if(complete)
            {
                MessagePrivate * e = new MessagePrivate;
                e->_message = tr("Protocol message size error");
                emit error(e);
                closeConnection();
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

        if(!authentication(data.data() + pos + MinimumPackageSize, size))
        {
            MessagePrivate * e = new MessagePrivate;
            e->_message = tr("Authorization error");
            emit error(e);
            closeConnection();
            return;
        }

        goto _next;

    _BackendKeyData : backendKeyData(data.data() + pos + MinimumPackageSize);
        goto _next;

    _NegotiateProtocolVersion :
    {
        MessagePrivate * e = new MessagePrivate;
        e->_message = tr("Protocol version 3.0 is not supported");
        emit error(e);
        closeConnection();
        return;
    }

    _default:
    {
        MessagePrivate * e = new MessagePrivate;
        e->_message = tr("Does not support the type of message in the protocol: ") + data[pos];
        emit error(e);
        closeConnection();
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
            MessagePrivate * e = new MessagePrivate;
            e->_message = tr("Data segmentation error");
            emit error(e);
            closeConnection();
        }

        _bufferIn = data.mid(pos);
        return;
    }
}

void ConnectionPrivateThread::sockDisconnected(){ closeConnection(); }

void ConnectionPrivateThread::sockNotice(const QString & notice)
{
    MessagePrivate * n = new MessagePrivate;
    n->_message = notice;
    emit this->notice(n);
}

void ConnectionPrivateThread::sockError(const QString & error)
{
    MessagePrivate * e = new MessagePrivate;
    e->_message = error;
    emit this->error(e);
}

void ConnectionPrivateThread::sockLoop()
{
    if(!_state.load(std::memory_order_relaxed)) closeConnection();
}

void ConnectionPrivateThread::close()
{
    _state.store(false);
}



ConnectionPrivate::ConnectionPrivate(): worker(new ConnectionPrivateThread)
{
    worker->moveToThread(&thread);

    connect(this, &ConnectionPrivate::connection, worker.get(), &ConnectionPrivateThread::connection);

    connect(worker.get(), &ConnectionPrivateThread::connected, this, [this](){ isConn = true; });
    connect(worker.get(), &ConnectionPrivateThread::connected, this, &ConnectionPrivate::connected);

    connect(worker.get(), &ConnectionPrivateThread::disconnected, this, [this](){ isConn = false; });
    connect(worker.get(), &ConnectionPrivateThread::disconnected, this, &ConnectionPrivate::disconnected);

    connect(worker.get(), &ConnectionPrivateThread::error, this, &ConnectionPrivate::error);
    connect(worker.get(), &ConnectionPrivateThread::notice, this, &ConnectionPrivate::notice);

    thread.start();
}

ConnectionPrivate::~ConnectionPrivate()
{
    if(thread.isRunning())
    {
        close();
        thread.quit();
        thread.wait();
    }
}

std::weak_ptr<ConnectionPrivateThread> ConnectionPrivate::connectionThread(){ return worker; }

void ConnectionPrivate::close()
{
    worker->close();
}

}
