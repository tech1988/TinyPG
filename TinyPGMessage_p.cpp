#include "TinyPGMessage_p.h"

namespace TinyPG
{

QDebug operator << (QDebug debug, const MessagePrivate &error)
{
    QDebugStateSaver saver(debug);

    debug.nospace() << "Message(Importance: " << error._importance << ",\n";
    debug.nospace() << "        Code: " << error._code << ",\n";
    debug.nospace() << "        Message: " << error._message << ")";

    return debug;
}

}
