/*

epthpool_server.cpp

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <pthread.h>
#include <semaphore.h>
#include <sys/epoll.h>

#include <iostream>
#include <list>
#include <string>
using namespace std;

#include "packet.h"

//=== Global macro definitions =================//
#define WORKER_THREAD_COUNT 4
#define EP_POOL_SIZE 20

//=== Class and Structure definitions ==========//
class ClientData {
private:
  int mSock;

// personal datas
#define CLIENT_NAME_LIMIT RENAME_NAME_SIZE
  string mName;

public:
  ClientData() : mSock(-1) {}
  ClientData(int sockfd, const char *name = NULL) {
    mSock = sockfd;
    if (name != NULL) {
      mName = string(name, CLIENT_NAME_LIMIT);
    } else {
      char buf[CLIENT_NAME_LIMIT];
      sprintf(buf, "unnamed[%d]", mSock);
      mName = buf;
    }
  }
  ClientData(const ClientData &clntData) {
    mSock = clntData.mSock;
    mName = clntData.mName;
  }

  int GetSocket() { return mSock; }

  bool IsDisconnected() { return (mSock == -1 ? true : false); }

  bool Close() {
    if (mSock == -1)
      return false;
    close(mSock);
    mSock = -1;
    return true;
  }

  // methods for personal datas
  const string &GetName() { return mName; }
  void SetName(const char *name) { mName = string(name, CLIENT_NAME_LIMIT); }

  // networking methods
  bool SendData(const char *dataBuffer, unsigned int size) {
    if (mSock == -1 || dataBuffer == NULL)
      return false;

    int n = write(mSock, dataBuffer, size);
    if (n <= 0)
      return false;
    return true;
  }
};

/*
 ClientManager is implemented in terms of stl list
 This class guarantee a mutual extension for client list operation.
 (not for the each client element operation)
*/
class ClientManager {
private:
  list<ClientData> mClients;
  typedef list<ClientData>::iterator clnt_itr_t;

  sem_t rsem;
  sem_t wsem;
  int rcnt;
  int wcnt;

public:
  ClientManager() {
    sem_init(&rsem, 0, 1);
    sem_init(&wsem, 0, 1);
    rcnt = wcnt = 0;
  }
  ~ClientManager() {
    mClients.clear();
    sem_destroy(&rsem);
    sem_destroy(&wsem);
  }

  bool Add(int sockfd) {
    bool ok = false;

    startWrite();
    clnt_itr_t pExist = findClient(sockfd);
    if (pExist == mClients.end()) {
      mClients.push_back(ClientData(sockfd));
      ok = true;
    }
    endWrite();

    return ok;
  }

  bool CloseAndDelete(int sockfd) {
    bool ok = false;

    startWrite();
    clnt_itr_t pExist = findClient(sockfd);
    if (pExist != mClients.end()) {
      pExist->Close();
      mClients.erase(pExist);
      ok = true;
    }
    endWrite();

    return ok;
  }

  void SetClientName(int sockfd, const char *name) {
    startRead();
    clnt_itr_t pFind = findClient(sockfd);
    if (pFind != mClients.end())
      pFind->SetName(name);
    endRead();
  }

  const string GetClientName(int sockfd) {
    string name;

    startRead();
    clnt_itr_t pFind = findClient(sockfd);
    if (pFind != mClients.end())
      name = pFind->GetName();
    endRead();

    return name;
  }

  // return: send error count
  int MessageToAll(const char *msg, int exceptfd = -1) {
    int len = strlen(msg);
    int errcnt = 0;

    startRead();
    for (clnt_itr_t itr = mClients.begin(); itr != mClients.end(); itr++) {
      if (itr->GetSocket() == exceptfd)
        continue;
      if (!itr->SendData(msg, len)) {
        errcnt++;
      }
    }
    endRead();

    return errcnt;
  }

  int MessageTo(const char *to, const char *msg) {
    startRead();
    clnt_itr_t pExist = findClient(to);
    if (pExist != mClients.end())
      pExist->SendData(msg, strlen(msg));
    endRead();
  }

private:
  void startRead() {
    if (wcnt > 0) {
      sem_wait(&wsem);
      sem_post(&wsem);
    }
    if (rcnt == 0)
      sem_wait(&rsem);
    ++rcnt;
  }
  void endRead() {
    --rcnt;
    if (rcnt == 0)
      sem_post(&rsem);
  }

  void startWrite() {
    sem_wait(&wsem);
    ++wcnt;
    sem_wait(&rsem);
  }
  void endWrite() {
    sem_post(&rsem);
    --wcnt;
    sem_post(&wsem);
  }

  clnt_itr_t findClient(int sockfd) {
    clnt_itr_t itr = mClients.begin();
    for (; itr != mClients.end(); itr++) {
      if (itr->GetSocket() == sockfd)
        break;
    }
    return itr;
  }
  clnt_itr_t findClient(const char *name) {
    clnt_itr_t itr = mClients.begin();
    for (; itr != mClients.end(); itr++) {
      if (itr->GetName() == name)
        break;
    }
    return itr;
  }
};

class WorkQueue {
private:
  sem_t sem_notempt;
  pthread_mutex_t mtx;

  list<Packet> mQueue;

public:
  WorkQueue() {
    sem_init(&sem_notempt, 0, 0);
    pthread_mutex_init(&mtx, NULL);
  }
  ~WorkQueue() {
    sem_destroy(&sem_notempt);
    pthread_mutex_destroy(&mtx);
  }

  Packet Pop() {
    if (mQueue.empty()) {
      sem_wait(&sem_notempt);
    }

    pthread_mutex_lock(&mtx);
    Packet work = mQueue.front();
    mQueue.pop_front();
    pthread_mutex_unlock(&mtx);

    return work;
  }

  void Push(const Packet &work) {
    pthread_mutex_lock(&mtx);
    mQueue.push_back(work);
    if (mQueue.size() == 1) {
      sem_post(&sem_notempt);
    }
    pthread_mutex_unlock(&mtx);
  }
};

//=== Global variables ===============//
ClientManager *gpClntMgr = NULL;
WorkQueue *gpWorkQu = NULL;

bool gRun = true;

int fdEpoll = -1;
struct epoll_event ev;
struct epoll_event *evBuf = NULL;
int evCnt = 0;

//=== function declarations ==========//
void *fn_worker_thread(void *param) {
  Packet packet;
  char buf[BUFSIZ];

  while (gRun) {
    Packet packet = gpWorkQu->Pop();

    printf("packet received from %d\n", packet.fd);
    switch (packet.type) {
    case Packet::DATA_RENAME: {
      string oldName = gpClntMgr->GetClientName(packet.fd);

      gpClntMgr->SetClientName(packet.fd, ((Packet::Rename *)packet.data)->name);

      memset(buf, 0, BUFSIZ);
      sprintf(buf, "%s rename as %s", oldName.c_str(), ((Packet::Rename *)packet.data)->name);
      gpClntMgr->MessageToAll(buf);
    } break;

    case Packet::DATA_MESSAGE: {
      string name = gpClntMgr->GetClientName(packet.fd);

      memset(buf, 0, BUFSIZ);
      sprintf(buf, "%s: %s", name.c_str(), ((Packet::Message *)packet.data)->msg);
      if (((Packet::Message *)packet.data)->toAll) {
        gpClntMgr->MessageToAll(buf, packet.fd);
      } else {
        gpClntMgr->MessageTo(((Packet::Message *)packet.data)->to, buf);
      }
    } break;

    case Packet::DATA_UNKNOWN:
    default:
      break;
    }
  }
}

//=== main function ==================//
int main() {
  int fdListen = -1;
  struct sockaddr_in servaddr, clntaddr;
  unsigned int addrlen = sizeof(clntaddr);

  pthread_t workers[WORKER_THREAD_COUNT];

  int readn = 0;
  char buf[BUFSIZ];

  int i = 0;

  // create event buffer
  evBuf = (struct epoll_event *)malloc(sizeof(struct epoll_event) * EP_POOL_SIZE);

  fdEpoll = epoll_create(100);
  if (fdEpoll == -1) {
    printf("failed to create epoll pool\n");
    return -1;
  }

  // create socket
  fdListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fdListen == -1) {
    printf("failed to create socket\n");
    return -1;
  }

  // bind port and program
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(12345);

  if (bind(fdListen, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
    printf("failed to bind\n");
    return -1;
  }

  // listen
  if (listen(fdListen, 5) == -1) {
    printf("failed to create listen queue\n");
    return -1;
  }

  // initialize client manager
  gpClntMgr = new ClientManager();
  gpWorkQu = new WorkQueue();

  // create threads
  for (i = 0; i < WORKER_THREAD_COUNT; i++) {
    pthread_create(&workers[i], NULL, fn_worker_thread, NULL);
  }

  // add listen fd to event pool as listening socket
  ev.events = EPOLLIN;
  ev.data.fd = fdListen;
  epoll_ctl(fdEpoll, EPOLL_CTL_ADD, fdListen, &ev);

  // accepting
  while (true) {
    evCnt = epoll_wait(fdEpoll, evBuf, EP_POOL_SIZE, -1);
    if (evCnt == -1) {
      printf("error on epoll (epoll_wait)\n");
      return -1;
    }

    for (i = 0; i < evCnt; i++) {
      if (evBuf[i].data.fd == fdListen) {
        // acception
        int tmpfd = -1;
        memset(&clntaddr, 0, addrlen);
        tmpfd = accept(fdListen, (struct sockaddr *)&clntaddr, &addrlen);
        if (tmpfd == -1) {
          printf("failed to accept client\n");
          continue;
        }

        gpClntMgr->Add(tmpfd);

        ev.events = EPOLLIN;
        ev.data.fd = tmpfd;
        epoll_ctl(fdEpoll, EPOLL_CTL_ADD, tmpfd, &ev);
        printf("%d is connected\n", tmpfd);
      } else {
        if (evBuf[i].events == EPOLLIN) {
          Packet packetBuf;
          int tmpfd = evBuf[i].data.fd;
          readn = read(tmpfd, (char *)&packetBuf, sizeof(Packet));

          if (readn == -1) {
            epoll_ctl(fdEpoll, EPOLL_CTL_DEL, tmpfd, evBuf);

            string name = gpClntMgr->GetClientName(tmpfd);
            gpClntMgr->CloseAndDelete(tmpfd);

            memset(buf, 0, BUFSIZ);
            sprintf(buf, "%s is disconnected", name.c_str());
            printf("%s\n", buf);
            // gpClntMgr->MessageToAll(buf);
            continue;
          }
          if (readn == 0) {
            epoll_ctl(fdEpoll, EPOLL_CTL_DEL, tmpfd, evBuf);

            string name = gpClntMgr->GetClientName(tmpfd);
            gpClntMgr->CloseAndDelete(tmpfd);

            memset(buf, 0, BUFSIZ);
            sprintf(buf, "%s is gone", name.c_str());
            gpClntMgr->MessageToAll(buf);
            continue;
          }

          packetBuf.fd = tmpfd;
          gpWorkQu->Push(packetBuf);
        } else {
          printf("main thread> get strange event (%d) of fd(%d)\n", evBuf[i].events, evBuf[i].data.fd);
        }
      }
    }
  }

  close(fdListen);
  free(evBuf);

  delete gpWorkQu;
  delete gpClntMgr;

  return 0;
}