#include "TinyPG.h"
#include "TinyPGField_p.h"
#include "TinyPGMessage_p.h"
#include "TinyPGQuery_p.h"
#include "TinyPGConnection_p.h"

namespace TinyPG
{

Field::Field(FieldPrivate * p):p(p){}

Field::Field(const Field & other):p(other.p)
{
    p->counter++;
}

Field::Field(Field && other)
{
    p = other.p;
    other.p = nullptr;
}


Field::~Field()
{
    if(p == nullptr) return;

    p->counter--;

    if(p->counter.load() == 0) delete p;
}

Field & Field::operator=(const Field & other)
{
    p->counter--;

    if(p->counter.load() == 0) delete p;

    other.p->counter++;
    p = other.p;

    return *this;
}

Field & Field::operator=(Field && other)
{
    qSwap(p,other.p);

    return *this;
}

bool Field::operator==(const Field & other)
{
    if(p == other.p) return true;

    return *p == *other.p;
}

bool Field::operator!=(const Field & other)
{
    if(p == other.p) return false;

    return *p != *other.p;
}

const QString & Field::name() const { return p->_name; }

quint32 Field::tableOID() const { return p->_tableOID; }

quint16 Field::columnIndex() const { return p->_columnIndex; }

quint32 Field::typeOID() const { return p->_typeOID; }

qint16 Field::typeSize() const { return p->_typeSize; }

qint32 Field::typeModifier() const { return p->_typeModifier; }

quint16 Field::formatType() const { return p->_formatType; }

QMetaType::Type Field::type() const { return p->_type; }

QDebug operator << (QDebug debug, const Field & field)
{
    qDebug() << *field.p;
    return debug;
}

Message::Message(MessagePrivate * p):p(p){}

Message::Message(const Message &other):p(other.p)
{
    p->counter++;
}

Message::Message(Message &&other)
{
    p = other.p;
    other.p = nullptr;
}

Message::~Message()
{
    if(p == nullptr) return;

    p->counter--;

    if(p->counter.load() == 0) delete p;
}

Message & Message::operator=(const Message & other)
{
    p->counter--;

    if(p->counter.load() == 0) delete p;

    other.p->counter++;
    p = other.p;

    return *this;
}

Message & Message::operator=(Message && other)
{
    qSwap(p,other.p);

    return *this;
}

const QString & Message::importance() const { return p->_importance; }

const QString & Message::code() const { return p->_code; }

const QString & Message::message() const { return p->_message; }

QDebug operator << (QDebug debug, const Message & message)
{
   qDebug() << *message.p;
   return debug;
}



Query::Query(const Connection &connection):p(new QueryPrivate(connection.p->connectionThread()))
{
   connect(p, &QueryPrivate::executeFinished, this, &Query::executeFinished);
   connect(p, &QueryPrivate::prepareFinished, this, &Query::prepareFinished);
   connect(p, &QueryPrivate::notDone, this, &Query::notDone);
   connect(p, &QueryPrivate::error, this, &Query::error);
   connect(p, &QueryPrivate::notice, this, &Query::notice);
}

Query::Query(const Query & other):p(other.p)
{
   p->counter++;
}

Query::Query(Query && other)
{
   p = other.p;
   other.p = nullptr;
}

Query::~Query()
{
   if(p == nullptr) return;

   p->counter--;

   if(p->counter.load() == 0) delete p;
}

const Query & Query::operator=(const Query & other)
{
   p->counter--;

   if(p->counter.load() == 0) delete p;

   other.p->counter++;
   p = other.p;

   return *this;
}

const Query & Query::operator=(Query && other)
{
   qSwap(p,other.p);

   return *this;
}

bool Query::operator==(const Query & other)
{
   return p == other.p;
}

bool Query::operator!=(const Query & other)
{
   return p != other.p;
}

bool Query::isLock() const { return p->isLock(); }

bool Query::hasConnection() const { return p->hasConnection(); }

const QString & Query::lastQuery() const { return p->lastQuery(); }

bool Query::exec(){ return p->exec(); }

bool Query::exec(const QString & query) { return p->exec(query); }

bool Query::prepare(const QString & query) { return p->prepare(query); }

int Query::preparedParameterCount() const { return p->preparedParameterCount(); }

QMetaType::Type Query::preparedParameterType(int index) const { return p->preparedParameterType(index); }

quint32 Query::preparedParametrOid(int index) const { return p->preparedParametrOid(index); }

int Query::bindCount() const { return p->bindCount(); }

void Query::bindValue(int index, const std::variant<qint16, QVariant> &value) { p->bindValue(index, value); }

QMetaType::Type Query::bindedType(int index) const { return p->bindedType(index); }

QVariant Query::bindedValue(int index) const { return p->bindedValue(index); }

int Query::fieldCount() const { return p->fieldCount(); }

const Field & Query::field(int index) const { return p->field(index); }

int Query::rowCount() const { return p->rowCount(); }

int Query::columnCount() const { return p->columnCount(); }

QVariant Query::value(int row, int column) const { return p->value(row, column); }

QDebug operator << (QDebug debug, const Query & query)
{
   qDebug() << *query.p;
   return debug;
}



Connection::Connection():p(new ConnectionPrivate)
{
   qRegisterMetaType<const Message&>();

   connect(p, &ConnectionPrivate::connected, this, &Connection::connected);
   connect(p, &ConnectionPrivate::disconnected, this, &Connection::disconnected);
   connect(p, &ConnectionPrivate::error, this, &Connection::error);
   connect(p, &ConnectionPrivate::notice, this, &Connection::notice);
}

Connection::Connection(const Connection & other):p(other.p)
{
   p->counter++;
}

Connection::Connection(Connection && other)
{
   p = other.p;
   other.p = nullptr;
}

Connection::~Connection()
{
   if(p == nullptr) return;

   p->counter--;

   if(p->counter.load() == 0) delete p;
}

const Connection & Connection::operator=(const Connection & other)
{
   p->counter--;

   if(p->counter.load() == 0) delete p;

   other.p->counter++;
   p = other.p;

   return *this;
}

const Connection & Connection::operator=(Connection && other)
{
   qSwap(p,other.p);

   return *this;
}

bool Connection::operator==(const Connection & other)
{
   return p == other.p;
}

bool Connection::operator!=(const Connection & other)
{
   return p != other.p;
}

bool Connection::isConnected() const
{
   return p->isConn;
}

void Connection::connection(const QString &host, quint16 port, const QString & user, const QString & password, const QString & database)
{
   emit p->connection(host, port, user, password, database);
}

void Connection::close(){ p->close(); }

}
