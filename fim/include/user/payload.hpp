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

static inline std::string escapeJsonString(const std::string& input) {
  std::string output;
  output.reserve(input.length());
  for (char c : input) {
    if (c == '"') {
      output += "\\\"";
    } else if (c == '\\') {
      output += "\\\\";
    } else if (c == '\b') {
      output += "\\b";
    } else if (c == '\f') {
      output += "\\f";
    } else if (c == '\n') {
      output += "\\n";
    } else if (c == '\r') {
      output += "\\r";
    } else if (c == '\t') {
      output += "\\t";
    } else if (static_cast<unsigned char>(c) <= 0x1f) {
      char buf[8];
      snprintf(buf, sizeof(buf), "\\u%04x", c);
      output += buf;
    } else {
      output += c;
    }
  }
  return output;
}

static inline std::string serializePayload(const Payload *p) {
  return "{\"file_path\":\"" + escapeJsonString(p->file_path) + "\",\"tty\":\"" + escapeJsonString(p->tty) +
         "\",\"username\":\"" + escapeJsonString(p->username) + "\",\"from_ip\":\"" + escapeJsonString(p->from_ip) +
         "\",\"timestamp\":\"" + escapeJsonString(p->time_stamp) + "\",\"change_type\":\"" +
         escapeJsonString(p->change_type) + "\",\"checksum\":\"" + escapeJsonString(p->checksum) +
         "\",\"before_size\":\"" + p->before_size + "\",\"after_size\":\"" +
         p->after_size + "\",\"file_size\":\"" + p->file_size + "\"}";
}

#endif /* PAYLOAD_H */