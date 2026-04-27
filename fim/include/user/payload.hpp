#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <string>

struct Payload {
  std::string file_path;
  std::string tty;
  std::string username;
  std::string from_ip;
  std::string time_stamp;
  std::string change_type;
  std::string checksum;
  std::string before_size;
  std::string after_size;
  std::string file_size;
};

static inline std::string serializePayload(const Payload *p) {
  return "{\"file_path\":\"" + p->file_path + "\",\"tty\":\"" + p->tty +
         "\",\"username\":\"" + p->username + "\",\"from_ip\":\"" + p->from_ip +
         "\",\"timestamp\":\"" + p->time_stamp + "\",\"change_type\":\"" +
         p->change_type + "\",\"checksum\":\"" + p->checksum +
         "\",\"before_size\":\"" + p->before_size + "\",\"after_size\":\"" +
         p->after_size + "\",\"file_size\":\"" + p->file_size + "\"}";
}

#endif /* PAYLOAD_H */