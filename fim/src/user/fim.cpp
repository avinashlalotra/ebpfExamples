#include "cmdline.hpp"
#include "daemon.hpp"
#include "event.hpp"
#include "logging.hpp"
#include "parser.hpp"
#include "processevent.hpp"
#include "shared_types.h"
#include "userspacefilter.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <csignal>
#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include <syslog.h>
#include <thread>
#include <unistd.h>

extern "C" {
#include "fentry_bpf.skel.h"
}

ProcessEvent peventobj;
UserspaceFilter filter;
Logger logger;

static volatile sig_atomic_t signal_received = 0;
void handle_signal(int) { signal_received = 1; }

int load_Inode_map(Parser *obj, fentry_bpf *skel) {
  __u32 size = (__u32)obj->include_dir->size();
  int mapfd = bpf_map__fd(skel->maps.InodeMap);

  if (mapfd < 0) {
    fprintf(stderr, "Failed to get map fd\n");
    return -1;
  }

  std::vector<KEY> keys;
  std::vector<VALUE> values;

  for (auto &[key, value] : *obj->include_dir) {
    keys.push_back(key);
    values.push_back(value);
  }

  int err =
      bpf_map_update_batch(mapfd, keys.data(), values.data(), &size, NULL);
  if (err) {
    fprintf(stderr, "Failed to update map\n");
    return -1;
  }
  fprintf(stderr, "Successfully updated map\n");
  return 0;
}

Cmdline::Cmdline() {
  version = "0.01";
  help_text = R"(
                 fim [command]

                 commands :  [version, validate, status, stop, run, log]

                 version | version info
                 validates | validate config file syntax
                 status | Deamon status active or not
                 stop | stop the deamon
                 run | starts the deamon
                 log | fetches logs from syslog
                  
                  )";
  validate = false;
  config = "/etc/fim/config.txt";
  pid = "/var/run/fim.pid";
}

int Cmdline::parse(int argc, const char **argv) {
  if (argc == 2) {
    if (strcmp(argv[1], "run") == 0) {
      return run();
    }
    if (strcmp(argv[1], "status") == 0) {
      return status();
    }
    if (strcmp(argv[1], "validate") == 0) {
      return validate_config();
    }
    if (strcmp(argv[1], "version") == 0) {
      return print_version();
    }
    if (strcmp(argv[1], "log") == 0) {
      return print_log();
    }
    if (strcmp(argv[1], "stop") == 0) {
      return stop();
    }
  }

  return print_help();
}

int Cmdline::run() {
  Events *events;
  std::thread producer_thread;
  std::thread consumer_thread;
  Parser *parser;
  int err;
  fentry_bpf *skel;

  fprintf(stderr, "Starting program\n");
  parser = new Parser(config);

  err = parser->compile();
  if (err) {
    fprintf(stderr, "Failed to compile parser\n");
    return 1;
  }
  fprintf(stderr, "Successfully compiled parser\n");

  skel = fentry_bpf::open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open skeleton\n");
    return 1;
  }
  fprintf(stderr, "Successfully opened skeleton\n");

  err = fentry_bpf::attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach skeleton\n");
    goto cleanup;
  }
  fprintf(stderr, "Successfully attached skeleton\n");

  load_Inode_map(parser, skel);
  fprintf(stderr, "Successfully loaded map\n");

  peventobj.initProcessEvent();
  fprintf(stderr, "Successfully initialized process event\n");

  filter.initFilter(parser);
  fprintf(stderr, "Successfully initialized filter\n");

  logger.init(parser);
  fprintf(stderr, "Successfully initialized logger\n");
  delete parser;
  events = new Events(skel->maps.rb);

  printf("Successfully started!\n");
  printf("Run: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
  // Config validation passed, now daemonize
  Daemon::init(pid.c_str());

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  producer_thread = std::thread([&]() { events->producer(); });
  consumer_thread = std::thread([&]() { events->consumer(); });

  while (!signal_received) {
    pause();
  }

  events->stop();
  producer_thread.join();
  consumer_thread.join();
  delete events;

cleanup:
  fentry_bpf::destroy(skel);
  syslog(LOG_INFO, "Successfully cleaned up");
  return err;
}

int Cmdline::status() {
  FILE *pidFile = fopen(pid.c_str(), "r");
  if (!pidFile) {
    printf("Status: Not active (PID file not found)\n");
    return 1;
  }

  pid_t p;
  if (fscanf(pidFile, "%d", &p) == 1) {
    fclose(pidFile);
    if (kill(p, 0) == 0) {
      // Check if the process name actually matches to handle PID reuse
      char procPath[256];
      snprintf(procPath, sizeof(procPath), "/proc/%d/comm", p);
      FILE *commFile = fopen(procPath, "r");
      if (commFile) {
        char commName[256] = {0};
        if (fscanf(commFile, "%255s", commName) == 1 &&
            strstr(commName, "fim") != NULL) {
          printf("Status: active\n");
          fclose(commFile);
          return 0;
        } else {
          printf("Status: Not active (process not running, PID was reused by "
                 "%s)\n",
                 commName);
          fclose(commFile);
          return 1;
        }
      } else {
        printf("Status: active (could not verify process name)\n");
        return 0;
      }
    } else {
      printf("Status: Not active (process not running)\n");
      return 1;
    }
  }

  fclose(pidFile);
  printf("Status: Not active (invalid PID file)\n");
  return 1;
}

int Cmdline::validate_config() {
  Parser parser(config);
  if (parser.tokenize() != 0) {
    fprintf(stderr, "Validation failed: Tokenization error.\n");
    return 1;
  }
  if (parser.syntaxValidation() != 0) {
    fprintf(stderr, "Validation failed: Syntax error.\n");
    return 1;
  }
  printf("Configuration file is valid.\n");
  return 0;
}

int Cmdline::print_version() {
  printf("%s\n", version.c_str());
  return 0;
}

int Cmdline::print_log() {
  printf("Fetching recent logs for fim...\n");
  // Try journalctl first (standard on systemd systems)
  int ret = system("journalctl -t fim --no-pager -n 50");
  if (ret != 0) {
    // Fallback to reading standard syslog files
    printf("\nFalling back to standard syslog...\n");
    system("grep 'fim\\[' /var/log/syslog /var/log/messages 2>/dev/null | tail "
           "-n 50");
  }
  return 0;
}

int Cmdline::print_help() {
  printf("%s\n", help_text.c_str());
  return -1;
}

int Cmdline::stop() {
  FILE *pidFile = fopen(pid.c_str(), "r");
  if (!pidFile) {
    fprintf(stderr,
            "Cannot stop: PID file not found. Is the daemon running?\n");
    return 1;
  }

  pid_t p;
  if (fscanf(pidFile, "%d", &p) == 1) {
    fclose(pidFile);

    if (kill(p, 0) == 0) {
      char procPath[256];
      snprintf(procPath, sizeof(procPath), "/proc/%d/comm", p);
      FILE *commFile = fopen(procPath, "r");
      if (commFile) {
        char commName[256] = {0};
        if (fscanf(commFile, "%255s", commName) == 1 &&
            strstr(commName, "fim") == NULL) {
          fprintf(stderr,
                  "Cannot stop: process running with PID %d is %s, not fim. "
                  "Stale PID file?\n",
                  p, commName);
          fclose(commFile);
          return 1;
        }
        fclose(commFile);
      }
    }

    if (kill(p, SIGTERM) == 0) {
      printf("Daemon stopped successfully.\n");
      remove(pid.c_str());
      return 0;
    } else {
      fprintf(stderr, "Failed to stop daemon (process not running or "
                      "permission denied).\n");
      return 1;
    }
  }

  fclose(pidFile);
  fprintf(stderr, "Invalid PID file.\n");
  return 1;
}

int main(int argc, const char **argv) {
  Cmdline cmd;
  return cmd.parse(argc, argv);
}