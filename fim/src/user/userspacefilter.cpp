#include "userspacefilter.hpp"
#include "parser.hpp"
#include "shared_types.h"

#include <cstdio>
#include <cstring>
#include <string>

#ifdef DEBUG_USERSPACE_FILTER
void UserspaceFilter::printFilter() const {

  printf("Exclude extension: ");
  for (const auto &ext : filter.exclude_extension) {
    printf("%s ", ext.first.c_str());
  }
  printf("\n");

  printf("Exclude suffix: ");
  for (const auto &suffix : filter.exclude_suffix) {
    printf("%s ", suffix.c_str());
  }
  printf("\n");

  printf("Exclude prefix: ");
  for (const auto &prefix : filter.exclude_prefix) {
    printf("%s ", prefix.c_str());
  }
  printf("\n");
}
#endif

UserspaceFilter::UserspaceFilter() {}

UserspaceFilter::~UserspaceFilter() {}

void UserspaceFilter::initFilter(void *parser) {

  Parser *parserObj = static_cast<Parser *>(parser);
  if (!parserObj) {
    printf("Parser object is null\n");
    return;
  }

  filter = *parserObj->getUserSpaceFilter();

#ifdef DEBUG_USERSPACE_FILTER
  printFilter();
#endif
}

bool UserspaceFilter::filterEvent(void *event) {

  EVENT *eventObj = static_cast<EVENT *>(event);
  if (!eventObj) {
    printf("Event object is null\n");
    return false;
  }

  // filter if bytes written are 0
  if (eventObj->change_type == WRITE_EVENT && eventObj->bytes_written == 0) {
    return true;
  }

  // filepath buffer -> string
  std::string filename(eventObj->filepath);

  // ---- extension check ----
  std::string ext;
  size_t pos = filename.rfind('.');

  if (pos != std::string::npos && pos + 1 < filename.size()) {
    ext = filename.substr(pos + 1);

    if (filter.exclude_extension.find(ext) != filter.exclude_extension.end()) {
      return true;
    }
  }

  // ---- suffix check ----
  for (const auto &suffix : filter.exclude_suffix) {

    if (filename.size() >= suffix.size() &&
        filename.compare(filename.size() - suffix.size(), suffix.size(),
                         suffix) == 0) {
      return true;
    }
  }

  // ---- pattern check ----
  for (const auto &pattern : filter.exclude_pattern) {

    if (std::regex_search(filename, pattern)) {
      return true;
    }
  }

  return false;
}
