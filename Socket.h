#ifndef SOCKET_H
#define SOCKET_H

#include <QString>

QString socketError();

#if !defined(WIN32)
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define closeSocket ::close

#else
#include <winsock2.h>
#include <ws2tcpip.h>

#define closeSocket closesocket

#endif

//desable write buffer?

namespace Communication
{

template<typename Observer> class Socket final
{
    Observer & observer;

    bool run = false, conn = false;

    QString host;
    qint16 port;

    int sock,
        connTimeOutSecs = 5, //5 secs
        waitTimeOutMs = 500000; //max 999ms darwin

    qsizetype w_offset = -1;
    QByteArray out;

    int connect()
    {
        struct addrinfo * result;

        int res = getaddrinfo(host.toLocal8Bit().data(), nullptr, nullptr, &result);

        if(res != 0)
        {

#if !defined(WIN32)
           if(res == EAI_SYSTEM)
           {
              observer.sockError(socketError());
           }
           else
           {
              observer.sockError(gai_strerror(res));
           }
#else
           observer.sockError(QString::fromWCharArray(gai_strerror(res)));
#endif
           return false;
        }

        for(struct addrinfo * addr = result; addr != nullptr; addr = addr->ai_next)
        {
            if(addr->ai_socktype != 0 && addr->ai_socktype != SOCK_STREAM) continue;

            if(addr->ai_family == AF_INET)
            {
                reinterpret_cast<sockaddr_in *>(addr->ai_addr)->sin_port = htons(port);
            }
            else if(addr->ai_family == AF_INET6)
            {
                reinterpret_cast<sockaddr_in6 *>(addr->ai_addr)->sin6_port = htons(port);
            }
            else continue;

            sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

            if(sock < 0)
            {
               observer.sockError(socketError());
               freeaddrinfo(result);
               return false;
            }

#if !defined(WIN32)
            if(fcntl(sock, F_SETFL, O_NONBLOCK) < 0)
            {
                observer.sockError(socketError());
                ::close(sock);
                freeaddrinfo(result);
                return false;
            }
#else
            unsigned long on = 1;
            if(ioctlsocket(sock, FIONBIO, &on) < 0)
            {
               observer.sockError(socketError());
               closeSocket(sock);
               freeaddrinfo(result);
               return false;
            }
#endif

            if(::connect(sock, addr->ai_addr, addr->ai_addrlen) < 0)
            {
#if !defined(WIN32)
                if(errno != EINPROGRESS)
#else
                if(WSAGetLastError() != WSAEWOULDBLOCK)
#endif
                {
                    observer.sockError(socketError());
                    closeSocket(sock);
                    freeaddrinfo(result);
                    return false;
                }
            }

            fd_set fd_out;
            struct timeval tv;

            tv.tv_sec = connTimeOutSecs;
            tv.tv_usec = 0;

            FD_ZERO(&fd_out);
            FD_SET(sock, &fd_out);

            res = select(sock + 1, nullptr, &fd_out, nullptr, &tv);

            if(res < 0)
            {
                observer.sockError(socketError());
                closeSocket(sock);
                freeaddrinfo(result);
                return false;
            }

            if(res == 0)
            {
                char address[INET6_ADDRSTRLEN];
                inet_ntop(addr->ai_family, addr->ai_addr, address, INET6_ADDRSTRLEN);
                observer.sockNotice(QLatin1String("Connection timeout: host '%1', address '%2', port '%3'").arg(host).arg(address).arg(port));
                closeSocket(sock);
                continue;
            }

            int err, len = sizeof(int);

#if !defined(WIN32)
            if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, reinterpret_cast<socklen_t *>(&len)) < 0)
#else
            if(getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&err), &len) < 0)
#endif
            {
                observer.sockError(socketError());
                closeSocket(sock);
                freeaddrinfo(result);
                return false;
            }

            if(err != 0)
            {
                observer.sockError(strerror(err));
                closeSocket(sock);
                freeaddrinfo(result);
                return false;
            }

            freeaddrinfo(result);
            return true;
        }

        observer.sockError("Connection failed");
        freeaddrinfo(result);
        return false;
    }

    void loop()
    {
        int sock_sl = sock + 1;

        fd_set fd_in, fd_out;
        struct timeval tv;

        tv.tv_sec = 0;
        tv.tv_usec = waitTimeOutMs;

        while(run || w_offset != -1)
        {
            FD_ZERO(&fd_in);
            FD_SET(sock, &fd_in);

            FD_ZERO(&fd_out);
            FD_SET(sock, &fd_out);

            int res = select(sock_sl, &fd_in, &fd_out, nullptr, &tv);

            if(res < 0)
            {
                observer.sockError(socketError());
                run = false;
                continue;
            }

            if(res == 0)
            {
               observer.sockLoop();
               continue;
            }

            if(FD_ISSET(sock, &fd_in)) observer.sockReadyRead();

            if(FD_ISSET(sock, &fd_out))
            {
                if(w_offset != -1)
                {
                    qsizetype res = send(sock, out.data() + w_offset, out.size() - w_offset, 0);

                    if(res < 0)
                    {
#if !defined(WIN32)
                        if(errno != EWOULDBLOCK)
#else
                        if(WSAGetLastError() != WSAEWOULDBLOCK)
#endif
                        {
                            observer.sockError(socketError());
                            run = false;
                        }

                        continue;
                    }

                    res += w_offset;

                    if(res == out.size()) w_offset = -1;
                    else w_offset = res;
                }
                else observer.sockLoop();
            }
        }

        closeSocket(sock);
        run = false;
    }

public:

    explicit Socket(Observer & observer):observer(observer){}

    ~Socket(){ this->close(); }

    void setConnectionTimeOutSecs(int secs = 5){ connTimeOutSecs = secs; }

    void setWaitTimeOutMs(int ms = 500){ waitTimeOutMs = std::min(ms * 1000, 999999); }

    void connectToHost(const QString & host, qint16 port)
    {
        run = true;

        this->host = host;
        this->port = port;

        if(connect())
        {
           conn = true;
           observer.sockConnected();
           loop();
           conn = false;
           observer.sockDisconnected();
        }
        else run = false;
    }

    void write(const QByteArray & data)
    {
        if(!run) return;

        qsizetype res = send(sock, data.data(), data.size(), 0);

        if(res < 0)
        {
#if !defined(WIN32)
            if(errno != EWOULDBLOCK)
#else
            if(WSAGetLastError() != WSAEWOULDBLOCK)
#endif
            {
                observer.sockError(socketError());
                run = false;
            }

            res = 0;
        }

        if(res != data.size())
        {
            w_offset = res;
            out = data;
        }
    }

    qsizetype read(char * data, size_t size)
    {
        if(!run) return 0;

        qsizetype res = recv(sock, data, size, 0);

        if(res < 0)
        {
#if !defined(WIN32)
            if(errno != EWOULDBLOCK)
#else
            if(WSAGetLastError() != WSAEWOULDBLOCK)
#endif
            {
                observer.sockError(socketError());
                run = false;
            }

            return 0;
        }

        return res;
    }

    bool isConnected(){ return conn; }

    void close(){ run = false; }
};

}

#endif // SOCKET_H
