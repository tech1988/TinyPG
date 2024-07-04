#ifndef TINYPGMESSAGEPRIVATE_H
#define TINYPGMESSAGEPRIVATE_H

#include <QDebug>

namespace TinyPG
{

class MessagePrivate final
{
    friend class Message;
    friend class ConnectionPrivateThread;
    friend QDebug operator << (QDebug debug, const MessagePrivate & error);

    std::atomic_uint64_t counter = 1;

    QString _importance, _code, _message;
};

QDebug operator << (QDebug debug, const MessagePrivate & error);

}

#endif // TINYPGMESSAGEPRIVATE_H
