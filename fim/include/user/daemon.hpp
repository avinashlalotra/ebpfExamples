#ifndef DAEMON_HPP
#define DAEMON_HPP

class Daemon {
public:
    static void init(const char* pid_file_path = "/var/run/fim.pid");
};

#endif // DAEMON_HPP
