#ifndef TINYPGCONNECTION_P_H
#define TINYPGCONNECTION_P_H

#include "Socket.h"
#include <QObject>
#include <QMap>
#include <QQueue>
#include <QThread>

#include "TinyPG.h"
#include "SCRAM_SHA256.h"

namespace TinyPG
{

class QueryPrivate;
class MessagePrivate;
class ConnectionPrivateThread final: public QObject
{
    Q_OBJECT

    friend class QueryPrivate;

public:
    explicit ConnectionPrivateThread();
    ~ConnectionPrivateThread();

    void sockConnected();
    void sockReadyRead();
    void sockDisconnected();
    void sockNotice(const QString & notice);
    void sockError(const QString & error);
    void sockLoop();

    void close();

public slots:
    void connection(const QString &host,
                    quint16 port,
                    const QString & user,
                    const QString & password,
                    const QString & database);

private:
    std::mutex mutex;

    Communication::Socket<ConnectionPrivateThread>_socket;

    QByteArray _bufferIn, _bufferOut;

    QByteArray _user, _password, _database;
    QMap<QString, QString> _parametersStatus;

    quint32 _pid = 0, _key = 0;

    std::atomic_bool _state = false;
    bool _auth_success = false;

    SCRAM_SHA256 * scram = nullptr;

    enum class ErrorOrNotice
    {
        Error,
        Notice
    };

    void closeConnection();

    void errorOrNoticeResponse(const char * data, quint32 size, ErrorOrNotice type);
    bool authentication(const char * data, quint32 size);
    void parameterStatus(const char * data);
    void backendKeyData(const char * data);
    void readyForQuery(const char * data);
    void rowDescription(const char * data);
    void preparedParametrs(const char * data, quint32 size);
    void dataRow(const char * data, quint32 size);

    void runQuery(QueryPrivate * query);
    void runPrepareQuery(QueryPrivate * query);
    void runBindQuery(QueryPrivate * query);

    QQueue<QueryPrivate *> _tasks;
    void taskFromQueue();
    void endTask();
    void addQuery(QueryPrivate * query);

signals:
    void connected();
    void disconnected();

    void error(const Message & error);
    void notice(const Message & notice);
};

class ConnectionPrivate final : public QObject
{
    Q_OBJECT

    friend class Connection;

    QThread thread;
    std::shared_ptr<ConnectionPrivateThread> worker;

    bool isConn = false;
    std::atomic_uint64_t counter = 1;

public:

    explicit ConnectionPrivate();

    ~ConnectionPrivate();

    std::weak_ptr<ConnectionPrivateThread> connectionThread();

public slots:
    void close();

signals:
    void connection(const QString &host, quint16 port, const QString & user, const QString & password, const QString & database);


    void connected();
    void disconnected();
    void error(const Message & error);
    void notice(const Message & notice);
};

}

#endif // TINYPGCONNECTION_P_H
