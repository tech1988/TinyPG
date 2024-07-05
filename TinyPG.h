#ifndef Connection_H
#define Connection_H

#include <QObject>
#include <QVariant>

namespace TinyPG
{
#if defined(SHARED_LIB)
#define SHARED Q_DECL_EXPORT
#else
#define SHARED
#endif

class FieldPrivate;
class SHARED Field final
{
   friend QDebug operator << (QDebug debug, const Field & query);
   friend class QueryPrivate;
   friend class ConnectionPrivateThread;

   Field(FieldPrivate * p);

public:
   Field() = delete;
   Field(const Field & other);
   Field(Field && other);
   ~Field();

   Field & operator=(const Field & other);
   Field & operator=(Field && other);

   bool operator==(const Field & other);
   bool operator!=(const Field & other);

   const QString & name() const;

   quint32 tableOID() const;

   quint16 columnIndex() const;

   quint32 typeOID() const;

   qint16 typeSize() const;

   qint32 typeModifier() const;

   quint16 formatType() const;

   QMetaType::Type type() const;

private:
   FieldPrivate * p;
};

QDebug operator << (QDebug debug, const Field & query);

class MessagePrivate;
class SHARED Message final
{
   friend QDebug operator << (QDebug debug, const Message & query);
   friend class ConnectionPrivateThread;

   Message(MessagePrivate * p);

public:
   Message() = delete;
   Message(const Message & other);
   Message(Message && other);
   ~Message();

   Message & operator=(const Message & other);
   Message & operator=(Message && other);

   const QString & importance() const;

   const QString & code() const;

   const QString & message() const;

private:
   MessagePrivate * p;
};

QDebug operator << (QDebug debug, const Message & query);

class Connection;
class QueryPrivate;
class SHARED Query final : public QObject
{
   Q_OBJECT

   friend QDebug operator << (QDebug debug, const Query & query);

public:
   Query() = delete;
   explicit Query(const Connection & connection);
   Query(const Query & other);
   Query(Query && other);
   ~Query();

   const Query & operator=(const Query & other);
   const Query & operator=(Query && other);

   bool operator==(const Query & other);
   bool operator!=(const Query & other);

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
   void bindValue(int index, const std::variant<qint16, QVariant> &value);
   QMetaType::Type bindedType(int index) const;
   QVariant bindedValue(int index) const;

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
   QueryPrivate * p;
};

QDebug operator << (QDebug debug, const Query & query);

class ConnectionPrivate;
class Connection final : public QObject
{
   Q_OBJECT

   friend class Query;

public:
   explicit Connection();
   Connection(const Connection & other);
   Connection(Connection && other);
   ~Connection();

   const Connection & operator=(const Connection & other);
   const Connection & operator=(Connection && other);

   bool operator==(const Connection & other);
   bool operator!=(const Connection & other);

   bool isConnected() const;

   void connection(const QString &host = "localhost",
                   quint16 port = 5432,
                   const QString & user = "postgres",
                   const QString & password = "postgres",
                   const QString & database = "postgres");

   void close();

signals:
   void connected();
   void disconnected();
   void error(const Message & error);
   void notice(const Message & notice);

private:
   ConnectionPrivate * p;
};

}

//Q_DECLARE_METATYPE(TinyPG::Message)

#endif
