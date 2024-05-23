#ifndef Connection_H
#define Connection_H

#include <QTcpSocket>
#include <QHostAddress>
#include <QTime>
#include <QTimeZone>
#include <QQueue>

namespace TinyPG
{

#if defined(SHARED_LIB)
#define SHARED Q_DECL_EXPORT
#else
#define SHARED
#endif

class SHARED Field final
{
    friend class Connection;
    friend class Query;
    friend QDebug operator << (QDebug debug, const Field & field);

    QString _name;
    quint32 _tableOID;
    quint16 _columnIndex;
    quint32 _typeOID;
    qint16 _typeSize;
    qint32 _typeModifier;
    quint16 _formatType;
    QMetaType::Type _type;

    explicit Field();
public:
    const QString & name() const;
    quint32 tableOID() const;
    quint16 columnIndex() const;
    quint32 typeOID() const;
    qint16 typeSize() const;
    qint32 typeModifier() const;
    quint16 formatType() const;
    QMetaType::Type type() const;
};

QDebug operator << (QDebug debug, const Field & field);


class SHARED Message
{
    friend class Connection;
    friend QDebug operator << (QDebug debug, const Message & error);

    QString _importance, _code, _message;

public:
    const QString & importance() const;
    const QString & code() const;
    const QString & message() const;
};

QDebug operator << (QDebug debug, const Message & error);


class Query;
class SHARED Connection final: public QObject
{
    Q_OBJECT

    friend class Query;

public:
    explicit Connection(QObject * parent = nullptr);
    ~Connection();

    bool isConnect();
    void connection(const QHostAddress & address = QHostAddress::LocalHost,
                    quint16 port = 5432,
                    const QString & user = "postgres",
                    const QString & password = "postgres",
                    const QString & database = QString());

public slots:
    void close();

private:
    QByteArray _bufferIn, _bufferOut;
    QTcpSocket _socket;

    QByteArray _user, _password, _database;
    QMap<QString, QString> _parametersStatus;

    quint32 _pid = 0, _key = 0;
    bool _auth_success = false;

    enum class ErrorOrNotice
    {
         Error,
         Notice
    };

    void errorOrNoticeResponse(const char * data, quint32 size, ErrorOrNotice type);
    bool authentication(const char * data);
    void parameterStatus(const char * data);
    void backendKeyData(const char * data);
    void readyForQuery(const char * data);
    void rowDescription(const char * data);
    void preparedParametrs(const char * data, quint32 size);
    void dataRow(const char * data, quint32 size);
    void runQuery(Query * query);
    void runPrepareQuery(Query * query);
    void runBindQuery(Query * query);

    QQueue<Query *> _tasks;
    void taskFromQueue();
    void endTask();
    void addQuery(Query * query);

private slots:
    void makeStarupMessage();
    void analyzePacket();

signals:
    void connected();
    void disconnected();

    void error(const Message & error);
    void notice(const Message & notice);
};


class SHARED Query final: public QObject
{
    Q_OBJECT

    friend class Connection;
    friend QDebug operator << (QDebug debug, const Query & query);
    static quint64 _stmt_number;

public:

    explicit Query(Connection * db, QObject * parent = nullptr);
    ~Query();

    const QString & lastQuery() const;

    void exec();
    void exec(const QString & query);
    void prepare(const QString & query);

    const QVector<QVariant> & bindValues() const;
    void bindValue(int index, const std::variant<qint16,qint32,QVariant> & value);

    const QVector<Field> & fields() const;

    int rowCount() const;
    int columnCount() const;
    QVariant value(int row, int column) const;

signals:
    void executeFinished();
    void prepareFinished();

    void error(const Message & error);
    void notice(const Message & notice);

private:
    Connection * _db = nullptr;
    bool _prepare = false, _prepareFinished = false;

    QByteArray _stmtName;
    QString _lastQuery;

    QVector<Field> _fields;
    QVector<quint32> _preparedParametrs;

    QVector<QVariant> _bindValues;
    QVector<char *> _dataRows;

    void preparation(const QString & query);
    void addPreparedParametr(quint32 oid);
    void addDataRow(const char * data, quint32 size);
};

QDebug operator << (QDebug debug, const Query & query);

}

#endif
