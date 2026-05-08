#ifndef CMDLINE_H
#define CMDLINE_H

#include <string>

class Cmdline {
public:
  std::string version;
  std::string help_text;
  std::string config;
  std::string pid;
  bool validate;

  Cmdline();
  ~Cmdline() = default;

  int parse(int argc, const char **argv);

  virtual int run();
  virtual int status();
  virtual int validate_config();
  virtual int print_version();
  virtual int print_help();
  virtual int print_log();
  virtual int stop();
};

#endif