#ifndef SCRAM_SHA256_H
#define SCRAM_SHA256_H

#include <QObject>

class SCRAM_SHA256 final : public QObject
{
    QByteArray auth_msg;

    QByteArray saltPassword(QByteArray salt, int iter, QByteArray password);
    QByteArray clientProof(QByteArray saltPassword, QByteArray r, QByteArray msg);

public:
    explicit SCRAM_SHA256(QObject * parent = nullptr);

    QByteArray initialResponse();
    QByteArray finalResponse(QByteArray password, QByteArray msg);
};

#endif // SCRAM_SHA256_H
