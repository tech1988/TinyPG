#include <QCoreApplication>
#include "TinyPG.h"
#include <QEventLoop>
#include <QDateTime>
#include <QUuid>

void viewQuery(const TinyPG::Query & query)
{
    qDebug() << query;
    for(const auto & field : query.fields()) qDebug() << field;

    for(int r = 0; r < query.rowCount(); r++)
    {
        QDebug d = qDebug();
        for(int c = 0; c < query.columnCount(); c++) d << query.value(r,c);
    }
}

int main(int argc, char *argv[])
{

    QCoreApplication a(argc, argv);

    TinyPG::Connection db;
    db.connection(QHostAddress::LocalHost, 5432, "postgres", "postgres", "Test");

    QEventLoop loop;
    bool err = false;

    auto lambdaError = [&loop, &err](const TinyPG::Message & error)
    {

        qDebug() << error.message();
        err = true;
        loop.quit();

    };

    db.connect(&db, &TinyPG::Connection::connected, &loop, &QEventLoop::quit);
    db.connect(&db, &TinyPG::Connection::error, lambdaError);
    loop.exec();

    if(err) return 1;

    TinyPG::Query query(&db);
    query.connect(&query, &TinyPG::Query::prepareFinished, &loop, &QEventLoop::quit);
    query.connect(&query, &TinyPG::Query::executeFinished, &loop, &QEventLoop::quit);
    query.connect(&query, &TinyPG::Query::error, lambdaError);

    query.connect(&query, &TinyPG::Query::notice, [](const TinyPG::Message & notice)
    {
        qDebug() << notice.message();
    });

    query.exec("create extension if not exists \"uuid-ossp\"");
    loop.exec();

    if(err) return 1;

    query.exec("create table if not exists test("
               "id bigserial primary key,"
               "int_2 smallint not null default 32767,"
               "int_4 int not null default 2147483647,"
               "int_8 bigint not null default 9223372036854775807,"
               "flt_4 real not null default 1234.95,"
               "flt_8 double precision not null default 1239999999999.95,"
               "dt date not null default current_date,"
               "tm time without time zone not null default current_time,"
               "tm_tz time with time zone not null default current_time,"
               "dtm timestamp without time zone not null default current_timestamp,"
               "dtm_tz timestamp with time zone not null default current_timestamp,"
               "raw bytea not null default \'\\x9f0c1a5f\'::bytea,"
               "txt text not null default 'text data',"
               "uid uuid not null default uuid_generate_v4())");
    loop.exec();

    if(err) return 1;

    query.exec("insert into test (txt) select 'txt' || id::text  from pg_catalog.generate_series(0, 100) id where (select count(*) from test) < 100");
    loop.exec();

    if(err) return 1;

    query.exec("select * from test order by id");
    loop.exec();

    if(err) return 1;

    viewQuery(query);

    query.prepare("insert into test(id,int_2,int_4,int_8,flt_4,flt_8,dt,tm,tm_tz,dtm,dtm_tz,raw,txt,uid) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) on conflict(id) do nothing");
    loop.exec();

    if(err) return 1;

    qint64 id = 999999999999999;
    qint16 _short = 32767;
    qint64 _long = 9223372036854775807;
    float _float = 1234.95;
    double _double = 1239999999999.95;
    QDate _date = QDate::fromString("2024-05-18", "yyyy-MM-dd");
    QTime _tm = QTime::fromString("13:26:44");
    QDateTime _tm_tz = QDateTime::fromString("13:26:44.517 UTC+03","hh:mm:ss.zzz t"),
              _dtm = QDateTime::fromString("2024-05-18 13:26:44.517", "yyyy-MM-dd hh:mm:ss.zzz"),
              _dtm_tz = QDateTime::fromString("2024-05-18 10:26:44.517", "yyyy-MM-dd hh:mm:ss.zzz");

    QByteArray _raw = QByteArray::fromHex("9f0c1a5f");
    QString _txt = "txt123456789";
    QUuid _uid = QUuid("{1b4da763-2818-4aae-874f-2fc3368e247b}");

    query.bindValue(0, id);
    query.bindValue(1, _short);
    query.bindValue(2, 2147483647);
    query.bindValue(3, _long);
    query.bindValue(4, _float);
    query.bindValue(5, _double);
    query.bindValue(6, _date);
    query.bindValue(7, _tm);
    query.bindValue(8, _tm_tz);
    query.bindValue(9, _dtm);
    query.bindValue(10, _dtm_tz);
    query.bindValue(11, _raw);
    query.bindValue(12, _txt);
    query.bindValue(13, _uid);

    query.exec();
    loop.exec();

    if(err) return 1;

    query.prepare("select * from test where id = $1 "
                  "and int_2 = $2 "
                  "and int_4 = $3 "
                  "and int_8 = $4 "
                  "and flt_4 = $5 "
                  "and flt_8 = $6 "
                  "and dt = $7 "
                  "and tm between $8 and $9 "
                  "and tm_tz between $10 and $11 "
                  "and dtm between $12 and $13 "
                  "and dtm_tz between $14 and $15 "
                  "and raw = $16 "
                  "and txt = $17 "
                  "and uid = $18");
    loop.exec();

    if(err) return 1;

    query.bindValue(0, id);
    query.bindValue(1, _short);
    query.bindValue(2, 2147483647);
    query.bindValue(3, _long);
    query.bindValue(4, _float);
    query.bindValue(5, _double);
    query.bindValue(6, _date);

    query.bindValue(7, _tm);
    query.bindValue(8, QTime::fromString("13:26:45"));

    query.bindValue(9, _tm_tz);
    query.bindValue(10, QDateTime::fromString("13:26:45.517 UTC+03","hh:mm:ss.zzz t"));

    query.bindValue(11, _dtm);
    query.bindValue(12, QDateTime::fromString("2024-05-18 13:26:45.517", "yyyy-MM-dd hh:mm:ss.zzz"));
    query.bindValue(13, _dtm_tz);
    query.bindValue(14, QDateTime::fromString("2024-05-18 10:26:45.517", "yyyy-MM-dd hh:mm:ss.zzz"));

    query.bindValue(15, _raw);
    query.bindValue(16, _txt);
    query.bindValue(17, _uid);

    query.exec();
    loop.exec();

    if(err) return 1;

    viewQuery(query);

    return 0;
}
