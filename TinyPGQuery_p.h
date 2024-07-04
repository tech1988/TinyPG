#ifndef TINYPGQUERYPRIVATE_H
#define TINYPGQUERYPRIVATE_H

#include <QDebug>
#include <QObject>
#include "TinyPGField_p.h"
#include "TinyPG.h"

namespace TinyPG
{

class ConnectionPrivateThread;
class MessagePrivate;
class QueryPrivate final: public QObject
{
    Q_OBJECT

    friend class Query;
    friend class ConnectionPrivateThread;
    friend QDebug operator << (QDebug debug, const QueryPrivate & QueryPrivate);
    static quint64 _stmt_number;

public:
    QueryPrivate() = delete;
    explicit QueryPrivate(std::weak_ptr<ConnectionPrivateThread> && db);
    ~QueryPrivate();

    bool isLock() const;
    bool hasConnection() const;

    const QString & lastQuery() const;

    bool exec();
    bool exec(const QString & query);
    bool prepare(const QString & query);

    int preparedParameterCount() const;
    QMetaType::Type preparedParameterType(int index) const;
    quint32 preparedParametrOid(int index) const;

    int bindCount() const;
    bool bindValue(int index, const std::variant<qint16, QVariant> &value);
    QMetaType::Type bindedType(int index) const;
    const QVariant & bindedValue(int index) const;

    int fieldCount() const;
    const Field & field(int index) const;

    int rowCount() const;
    int columnCount() const;
    QVariant value(int row, int column) const;

signals:
    void executeFinished();
    void prepareFinished();
    void notDone();

    void error(const Message & error);
    void notice(const Message & notice);

private:
    std::atomic_bool lock = false;
    std::atomic_uint64_t counter = 1;

    std::weak_ptr<ConnectionPrivateThread> _db;
    bool _prepare = false, _prepareFinished = false;

    QByteArray _stmtName;
    QString _lastQuery;

    QVector<Field> _fields;
    QVector<quint32> _preparedParameters;

    QVector<QVariant> _bindValues;
    QVector<char *> _dataRows;

    void preparation(std::shared_ptr<ConnectionPrivateThread> &db, const QString & query);
    void addPreparedParametr(quint32 oid);
    void addDataRow(const char * data, quint32 size);
};

QDebug operator << (QDebug debug, const QueryPrivate & query);

}

#endif // TINYPGQueryPrivatePRIVATE_H
