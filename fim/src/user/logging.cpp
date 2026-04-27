#include "logging.hpp"
#include "parser.hpp"
#include "payload.hpp"
#include <cstdio>
#include <httplib.h>
#define DEBUG_LOGGER

void Logger::init(void *parser) {

  Parser *p = (Parser *)parser;

  int size = p->api_header->size();
  url = *p->api_url;

  if (url.empty()) {
    fprintf(stderr, "Logger::init Api url is empty.Loggging is disabled. \n");
    return;
  }

  if (size == 0) {
    fprintf(stderr,
            "Logger::init Api headers are empty.Loggging is disabled. \n");
    return;
  }

  for (const auto &header : *p->api_header) {
    this->headers[header.first] = header.second;
  }

  this->timeout_ms = 200;

#ifdef DEBUG_LOGGER
  printf("------DEBUGGING LOGGER------------\n");
  printf("Api url : %s\n", url.c_str());
  printf("API headers .................\n");

  for (auto &[key, val] : headers) {
    printf("{%s : %s}\n", key.c_str(), val.c_str());
  }

  printf("-------------------------------------\n");
#endif
}

void Logger::log(void *payload) {
  const Payload *p = (const Payload *)payload;
  std::string data = serializePayload(p);

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  httplib::SSLClient cli("10.182.0.73", 8443);
  cli.enable_server_certificate_verification(false); // for self-signed certs
#else
  // HTTPS requires SSL support — this path will fail
  fprintf(stderr, "Logger: HTTPS not supported\n");
  return;
#endif

  cli.set_connection_timeout(std::chrono::milliseconds(timeout_ms));

  httplib::Headers h;
  for (auto &[key, val] : headers) {
    h.insert({key, val});
  }

  auto res = cli.Post("/api/v1/file_integrity", h, data, "application/json");

  if (!res) {
    fprintf(stderr, "Logger: request failed\n");
    return;
  }

  if (res->status < 200 || res->status >= 300) {
    fprintf(stderr, "Logger: server rejected log HTTP %d\n", res->status);
    fprintf(stderr, "Status: %d\n", res->status);
    fprintf(stderr, "Body: %s\n", res->body.c_str());
  }
}

Logger::~Logger() {}