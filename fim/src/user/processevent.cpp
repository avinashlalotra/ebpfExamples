#include "processevent.hpp"
#include "shared_types.h"
#include <arpa/inet.h>
#include <ctime>
#include <ifaddrs.h>
#include <pwd.h>
#include <syslog.h>
#include <unistd.h>
#include <vector>

int ProcessEvent::initProcessEvent() {
  loadDrivers();
  return 0;
}

std::string ProcessEvent::resolveTty(int major, int minor) {
  auto it = driver_map.find(major);

  if (it == driver_map.end())
    return "Unknown";

  return it->second + "/" + std::to_string(minor);
}

Payload ProcessEvent::Process(EVENT *event) {

  Payload p;
#ifdef DEBUG_PROCESS_EVENT
  syslog(LOG_DEBUG, "Event: tty_major=%d, tty_minor=%d, uid=%d, change_type=%d, "
         "before_size=%lld, file_size=%lld, len=%d",
         event->tty_major, event->tty_minor, event->uid,
         static_cast<int>(event->change_type), event->before_size,
         event->file_size, event->len);
#endif

  p.tty = resolveTty(event->tty_major, event->tty_minor);
  p.username = resolveUserName(event->uid);
  p.from_ip = resolveIp();
  p.time_stamp = TimeStamp();
  p.change_type = changeType(event);
  p.checksum = "dummy";
  p.before_size = std::to_string(event->before_size);
  p.after_size = std::to_string(event->file_size);
  p.file_size = std::to_string(event->file_size);
  p.file_path = pathconstruction(event);

  return p;
}

std::string ProcessEvent::resolveUserName(int uid) {

  struct passwd *pw = getpwuid(uid);
  if (pw)
    return std::string(pw->pw_name);

  return "unknown";
}

void ProcessEvent::loadDrivers() {

  driver_map[4] = "/dev/tty";
  driver_map[136] = "/dev/pts";
  driver_map[5] = "/dev/console";
}

std::string ProcessEvent::resolveIp() {

  struct ifaddrs *ifaddr, *ifa;
  char host[INET_ADDRSTRLEN];

  if (getifaddrs(&ifaddr) == -1)
    return "0.0.0.0";

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

    if (ifa->ifa_addr == NULL)
      continue;

    if (ifa->ifa_addr->sa_family == AF_INET) {

      void *addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;

      inet_ntop(AF_INET, addr, host, INET_ADDRSTRLEN);

      if (std::string(host) != "127.0.0.1") {
        freeifaddrs(ifaddr);
        return host;
      }
    }
  }

  freeifaddrs(ifaddr);
  return "0.0.0.0";
}

std::string ProcessEvent::TimeStamp() {

  std::time_t now = std::time(nullptr);

  // IST offset = 5 hours 30 minutes
  now += (5 * 3600 + 30 * 60);

  std::tm *tm_info = std::gmtime(&now);

  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);

  return std::string(buf);
}

std::string ProcessEvent::changeType(EVENT *event) {

  switch (event->change_type) {
  case CREATE_EVENT:
    return "CREATE";
  case DELETE_EVENT:
    return "DELETE";
  case WRITE_EVENT:
    return "MODIFY[" + std::to_string(event->bytes_written) + "]";
  case RENAME_C_EVENT:
    return "RENAME_C";
  case RENAME_D_EVENT:
    return "RENAME_D";
  case RENAME_OW_EVENT:
    return "RENAME_OW";
  case WRITE_INTENT:
    return "WRITE_INTENT";
  default:
    return "UNKNOWN";
  }
}

void ProcessEvent::print_event(Payload *p) {

  syslog(LOG_INFO,
      "Event: username=%s, change_type=%s, file_path=%s, tty=%s, from_ip=%s, "
      "timestamp=%s, before_size=%s, after_size=%s, file_size=%s",
      p->username.c_str(), p->change_type.c_str(), p->file_path.c_str(),
      p->tty.c_str(), p->from_ip.c_str(), p->time_stamp.c_str(),
      p->before_size.c_str(), p->after_size.c_str(), p->file_size.c_str());
  return;
}

std::string ProcessEvent::pathconstruction(EVENT *event) {

  std::vector<std::string> path;

  for (int i = 0; i < event->len; i++) {

    char buffer[PER_LEVEL];

    strncpy(buffer, event->filepath + i * PER_LEVEL, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    path.emplace_back(buffer);
  }

  std::string fullpath;

  for (auto it = path.rbegin(); it != path.rend(); ++it) {

    if (!it->empty()) {
      fullpath += "/";
      fullpath += *it;
    }
  }

  return fullpath;
}
