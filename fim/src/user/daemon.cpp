#include "daemon.hpp"
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <csignal>
#include <syslog.h>
#include <thread>
#include <string.h>
#include <stdio.h>

static void pipe_to_syslog(int fd, int priority) {
    char buf[1024];
    FILE *stream = fdopen(fd, "r");
    if (!stream) return;
    while (fgets(buf, sizeof(buf), stream) != NULL) {
        buf[strcspn(buf, "\n")] = 0;
        if (strlen(buf) > 0) {
            syslog(priority, "%s", buf);
        }
    }
}

void Daemon::init() {
    pid_t pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

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
    FILE *pid_file = fopen("/var/run/fim.pid", "w");
    if (pid_file) {
        fprintf(pid_file, "%d\n", getpid());
        fclose(pid_file);
    }

    // We don't close all FDs blindly because Daemon::init() is called 
    // at the very beginning of main(), so only standard FDs are open. 
    // Closing up to _SC_OPEN_MAX can be slow and unnecessary here.

    openlog("fim", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    int pipe_out[2], pipe_err[2];
    if (pipe(pipe_out) == 0 && pipe(pipe_err) == 0) {
        dup2(pipe_out[1], STDOUT_FILENO);
        dup2(pipe_err[1], STDERR_FILENO);
        close(pipe_out[1]);
        close(pipe_err[1]);

        std::thread(pipe_to_syslog, pipe_out[0], LOG_INFO).detach();
        std::thread(pipe_to_syslog, pipe_err[0], LOG_ERR).detach();
    }

    // Redirect standard input to /dev/null
    int fd0 = open("/dev/null", O_RDWR);
    if (fd0 != -1) {
        dup2(fd0, STDIN_FILENO);
        if (fd0 > 2) { // Just in case it's not 0, 1, or 2
            close(fd0);
        }
    }
}
