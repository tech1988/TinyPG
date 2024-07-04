#include "SCRAM_SHA256.h"

#include <QRandomGenerator>
#include <QMessageAuthenticationCode>
#include <QCryptographicHash>
#include <QMap>

QByteArray SCRAM_SHA256::saltPassword(QByteArray salt, int iter, QByteArray password)
{
    QByteArray iv = QByteArray::fromBase64(salt);
    const char one[] = {0x0,0x0,0x0,0x1};

    QMessageAuthenticationCode h(QCryptographicHash::Sha256, password);
    h.addData(iv);
    h.addData(QByteArray(one, sizeof(one)));

    QByteArray result = h.result(), previous;

    for(int i = 1; i < iter; i++)
    {
        h.reset();

        if(previous.isEmpty()) h.addData(result);
        else h.addData(previous);

        previous = h.result();

        for(int i = 0; i < result.size(); i++) result[i] ^= previous[i];
    }

    return result;
}

QByteArray SCRAM_SHA256::clientProof(QByteArray saltPassword, QByteArray r, QByteArray msg)
{
    QByteArray out = "c=biws,r=" + r;
    QByteArray client_key = QMessageAuthenticationCode::hash("Client Key", saltPassword, QCryptographicHash::Sha256);

    QByteArray client_signature = QMessageAuthenticationCode::hash(auth_msg + ',' + msg + ',' + out,
                                                                   QCryptographicHash::hash(client_key, QCryptographicHash::Sha256),
                                                                   QCryptographicHash::Sha256);

    for(int i = 0; i < client_key.size(); i++) client_key[i] ^= client_signature[i];

    return out + ",p=" + client_key.toBase64();
}

SCRAM_SHA256::SCRAM_SHA256(QObject * parent):QObject(parent){}

QByteArray SCRAM_SHA256::initialResponse()
{
    const char chs[] = "!\"#$%&'()*+-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    constexpr int chs_sz = sizeof(chs) - 2;

    QRandomGenerator * rg = QRandomGenerator::global();
    QByteArray gen;

    for(int i = 0; i < 24; i++) gen.append(chs[rg->bounded(0, chs_sz)]);

    auth_msg = "n=,r=" + gen;

    return "n,," + auth_msg;
}

QByteArray SCRAM_SHA256::finalResponse(QByteArray password, QByteArray msg)
{
    QMap<QChar, QByteArray> mp;

    for(auto arr : msg.split(','))
    {
        auto idx = arr.indexOf('=');

        if(idx != 1) continue;

        mp[arr[0]] = arr.mid(2);
    }

    if(!mp.contains('r') || !mp.contains('i') || !mp.contains('s')) return QByteArray();

    bool ok;
    int iter = mp['i'].toInt(&ok);

    if(!ok) return QByteArray();

    return clientProof(saltPassword(mp['s'], iter, password),mp['r'], msg);
}
