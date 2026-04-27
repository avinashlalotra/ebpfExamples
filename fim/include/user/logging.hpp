#ifndef LOGGING_HPP
#define LOGGING_HPP
#include <map>
#include <string>

class Logger {
public:
  void init(void *parser);
  void close();
  void log(void *payload);
  ~Logger();

private:
  std::string url;
  int port;
  std::map<std::string, std::string> headers;
  int timeout_ms = 5000;
};

#endif // LOGGING_HPP