#include "daemon.hpp"
#include <csignal>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

void Daemon::init(const char *pid_file_path) {

  /* fork and detach the parent */
  pid_t pid = fork();
  if (pid < 0) {
    exit(EXIT_FAILURE);
  }
  if (pid > 0) {
    exit(EXIT_SUCCESS);
  }

  /* new session */
  if (setsid() < 0) {
    exit(EXIT_FAILURE);
  }

  signal(SIGCHLD, SIG_IGN);
  signal(SIGHUP, SIG_IGN);

  pid = fork();
  if (pid < 0) {
    exit(EXIT_FAILURE);
  }
  if (pid > 0) {
    exit(EXIT_SUCCESS);
  }

  umask(0);

  // Write PID file for systemd/init process tracking
  FILE *pid_file = fopen(pid_file_path, "w");
  if (pid_file) {
    fprintf(pid_file, "%d\n", getpid());
    fclose(pid_file);
  }

  openlog("fim", LOG_PID | LOG_NDELAY, LOG_DAEMON);
}
