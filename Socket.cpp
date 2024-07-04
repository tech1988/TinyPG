#include "Socket.h"

#if defined(WIN32)

#include <QDebug>

QString socketError()
{
   wchar_t * str = nullptr;
   FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  nullptr, WSAGetLastError(),
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  reinterpret_cast<LPWSTR>(&str), 0, nullptr);
   QString ret = QString::fromWCharArray(str);
   LocalFree(str);
   return ret;
}

class WSAInit
{
   bool init = false;

public:
   WSAInit()
   {
      WSADATA wsaData;

      if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
      {
         qCritical() << socketError();
         return;
      }

      init = true;
   }

   ~WSAInit(){ if(init) WSACleanup(); }
};

WSAInit init;

#else

QString socketError(){ return strerror(errno); }

#endif
