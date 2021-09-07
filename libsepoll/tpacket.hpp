/*

packet.h

*/

#ifndef __PACKET_H__
#define __PACKET_H__

#include <stdlib.h>
#include <string.h>

#define DATA_NAME_LEN 32

class Packet {
  // data definitions
public:
#define MESSAGE_SIZE 128
#define MESSAGE_TO_ALL NULL
  class Message {
  public:
    char to[DATA_NAME_LEN];
    char msg[MESSAGE_SIZE];
    bool toAll;

    Message(const char *_to, const char *_msg) {
      memset(to, 0, DATA_NAME_LEN);
      if (_to != MESSAGE_TO_ALL) {
        int len = strlen(_to);
        if (len > DATA_NAME_LEN)
          len = DATA_NAME_LEN;
        strncpy(to, _to, len);
        toAll = false;
      } else
        toAll = true;

      int len = strlen(_msg);
      if (len > MESSAGE_SIZE)
        len = MESSAGE_SIZE;
      memset(msg, 0, MESSAGE_SIZE);
      strncpy(msg, _msg, len);
    }
    Message(const Message &message) {
      memcpy(to, message.to, sizeof(to));
      memcpy(msg, message.msg, sizeof(msg));
    }
  };

#define RENAME_NAME_SIZE DATA_NAME_LEN
  class Rename {
  public:
    char name[RENAME_NAME_SIZE];

    Rename(const char *_name) {
      int len = strlen(_name);
      if (len > RENAME_NAME_SIZE)
        ;
      len = RENAME_NAME_SIZE;
      memset(name, 0, RENAME_NAME_SIZE);
      strncpy(name, _name, len);
    }
    Rename(const Rename &rename) { memcpy(name, rename.name, sizeof(name)); }
  };

public:
  int fd;   // sender's socket fd
  int type; // packet data type
  enum { DATA_MESSAGE = 0, DATA_RENAME = 1, DATA_UNKNOWN = -1 };

#define PACKET_DATA_SIZE 256
  char data[PACKET_DATA_SIZE];

public:
  Packet() : fd(-1), type(-1) {}
  Packet(const Packet &packet) {
    fd = packet.fd;
    type = packet.type;
    memcpy(data, packet.data, sizeof(data));
  }

  Packet(int who, const Packet::Message &msgData) {
    fd = who;
    type = DATA_MESSAGE;
    memcpy(data, &msgData, sizeof(Packet::Message));
  }
  Packet(int who, const Packet::Rename &renameData) {
    fd = who;
    type = DATA_RENAME;
    memcpy(data, &renameData, sizeof(Packet::Rename));
  }
};

#endif