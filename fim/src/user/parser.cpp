#include "parser.hpp"
#include "shared_types.h"
#include "types.hpp"
#include <algorithm>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unordered_map>

#include <cerrno>
#include <cstring>

user_space_filter *Parser::getUserSpaceFilter() { return userSpaceFilter; }

std::pair<std::string, std::string> split_once(const std::string &str,
                                               char delim) {
  size_t pos = str.find(delim);

  if (pos == std::string::npos)
    return {str, ""};

  return {str.substr(0, pos), str.substr(pos + 1)};
}

Parser::Parser(const std::string &policyFilePath) {

  auto file = fopen(policyFilePath.c_str(), "r");
  if (!file) {
    fprintf(stderr, "Failed to open policy file: %s\n", policyFilePath.c_str());
    this->policyFilePath = "";
    return;
  }

  fclose(file);

  this->policyFilePath = policyFilePath;

  this->tokens = new std::vector<Token>();
  this->api_header = new std::vector<std::pair<std::string, std::string>>();
  this->api_url = new std::string;

  this->include_dir = new std::vector<std::pair<KEY, VALUE>>;
  this->exclude_dir = new std::unordered_map<std::string, int>;

  this->userSpaceFilter = new user_space_filter();
}

Parser::~Parser() {
  delete tokens;
  delete api_header;
  delete api_url;
  delete include_dir;
  delete exclude_dir;
  delete userSpaceFilter;
}

int Parser::tokenize() {

  // read the config file
  auto file = fopen(policyFilePath.c_str(), "r");
  if (!file) {
    fprintf(stderr, "Failed to open policy file: %s\n", policyFilePath.c_str());
    return -1;
  }

  char buffer[1024];
  int lineNumber = 1;
  while (fgets(buffer, sizeof(buffer), file)) {

    std::string line(buffer);

    if (!line.empty() && line.back() == '\n') {
      line.pop_back();
    }

    if (line.empty() || line.starts_with('#')) {
      lineNumber++;
      continue;
    }

    auto [command, argument] = split_once(line, ':');
    command.erase(std::remove_if(command.begin(), command.end(), ::isspace),
                  command.end());
    argument.erase(std::remove_if(argument.begin(), argument.end(), ::isspace),
                   argument.end());
    Token token(lineNumber, command, argument);
    tokens->push_back(token);
    lineNumber++;
  }

  fclose(file);

  if (tokens->empty()) {
    fprintf(stderr, "Token Gneration Failed . config file maybe empty\n");
    return -1;
  }

  return 0;
}

int Parser::syntaxValidation() {

  std::unordered_map<std::string, int> rules = {
      {"D", 1}, {"E", 1}, {"EE", 1}, {"ES", 1}, {"IF", 1}, {"EP", 1}, {"P", 1}};

  std::unordered_map<std::string, int> metadata = {{"API_URL", 1},
                                                   {"API_HEADER", 1}};

  for (const auto &token : *tokens) {
    if (rules.contains(token.command)) {
      continue;
    }
    if (metadata.contains(token.command)) {
      continue;
    }
    fprintf(stderr, "%s:%d: error: unknown command '%s'\n",
            policyFilePath.c_str(), token.lineNumber, token.command.c_str());

    return -1;
  }

  return 0;
}

int Parser::semanticValidation() {

  for (const auto &token : *tokens) {
    if (token.command == "D" || token.command == "E" || token.command == "IF") {

      if (!token.argument.starts_with("/")) {
        fprintf(
            stderr, "%s:%d: error: argument must be an absolute path '%s'\n",
            policyFilePath.c_str(), token.lineNumber, token.argument.c_str());
        return -1;
      }
      continue;
    }

    if (token.command == "EE") {
      if (token.argument.starts_with(".")) {
        fprintf(stderr,
                "%s:%d: error: EE argument should not include '.' in starting "
                "'%s'\n",
                policyFilePath.c_str(), token.lineNumber,
                token.argument.c_str());
        return -1;
      }
      continue;
    }

    if (token.command == "API_HEADER") {
      auto [name, value] = split_once(token.argument, '=');
      if (name.empty() || value.empty()) {
        fprintf(stderr, "%s:%d: error: invalid header format '%s'\n",
                policyFilePath.c_str(), token.lineNumber,
                token.argument.c_str());
        return -1;
      }
      continue;
    }

    if (token.command == "API_URL") {
      if (token.argument.empty()) {
        fprintf(stderr, "%s:%d: error: invalid url format '%s'\n",
                policyFilePath.c_str(), token.lineNumber,
                token.argument.c_str());
        return -1;
      }
      continue;
    }

    // suffix prefix and pattern check can be avoided
  }

  return 0;
}

#ifdef DEBUG_TOKENS

void Token::printToken() const {
  printf("Line %d: %s %s\n", lineNumber, command.c_str(), argument.c_str());
}
#endif

#ifdef DEBUG_PARSER

void Parser::printParser() const {
  printf("Tokens\n");
  for (const auto &token : *tokens) {
    token.printToken();
  }

  // print api url
  printf("API_URL\n");
  printf("API_URL: %s\n", api_url->c_str());

  // print api header
  printf("API_HEADER\n");
  for (const auto &header : *api_header) {
    printf("API_HEADER: %s=%s\n", header.first.c_str(), header.second.c_str());
  }

  // print exclude dir
  printf("Exclude dirs: \n");
  for (const auto &dir : *exclude_dir) {
    printf("E: %s\n", dir.first.c_str());
  }

  // print include dir
  printf("include dirs: \n");
  for (const auto &dir : *include_dir) {
    printf("D: %lld %lld\n", dir.first.inode, dir.first.dev);
  }

  // print exclude extension
  printf("Exclude extensions: \n");
  for (const auto &ext : userSpaceFilter->exclude_extension) {
    printf("EE: %s\n", ext.first.c_str());
  }

  // print exclude suffix
  printf("Exclude suffixes: \n");
  for (const auto &suffix : userSpaceFilter->exclude_suffix) {
    printf("ES: %s\n", suffix.c_str());
  }

  // print exclude prefix
  printf("Exclude prefixes: \n");
  for (const auto &prefix : userSpaceFilter->exclude_prefix) {
    printf("EP: %s\n", prefix.c_str());
  }
}
#endif
uint64_t st_to_dev_sb(dev_t st_dev) {
  unsigned int maj = major(st_dev);
  unsigned int min = minor(st_dev);

  return ((uint64_t)maj << 20) | min;
}
Token::Token(int lineNumber, const std::string &command,
             const std::string &argument) {
  this->lineNumber = lineNumber;
  this->command = command;
  this->argument = argument;
}

int Parser::parseRule(const Token &token) {

  struct stat st;

  if (stat(token.argument.c_str(), &st) != 0) {

    if (errno == ENOENT) {
      fprintf(stderr, "%s:%d: warning: path does not exist: %s\n",
              policyFilePath.c_str(), token.lineNumber, token.argument.c_str());
    } else if (errno == EACCES) {
      fprintf(stderr, "%s:%d: warning: permission denied: %s\n",
              policyFilePath.c_str(), token.lineNumber, token.argument.c_str());
    } else {
      fprintf(stderr, "%s:%d: warning: stat failed for '%s': %s\n",
              policyFilePath.c_str(), token.lineNumber, token.argument.c_str(),
              strerror(errno));
    }

    return -1;
  }

  KEY key{};
  VALUE value{};
  value.dummy = 1;

  key.inode = st.st_ino;
  key.dev = st_to_dev_sb(st.st_dev);

  if (exclude_dir->contains(token.argument))
    return 0;

  include_dir->push_back({key, value});

  if (!S_ISDIR(st.st_mode))
    return 0;

  if (token.command == "IF")
    return 0;

  for (auto it = std::filesystem::recursive_directory_iterator(
           token.argument,
           std::filesystem::directory_options::skip_permission_denied);
       it != std::filesystem::recursive_directory_iterator(); ++it) {

    const auto &entry = *it;
    auto path = entry.path().string();

    if (!entry.is_directory())
      continue;

    if (exclude_dir->contains(path)) {
      it.disable_recursion_pending();
      continue;
    }

    struct stat st2;

    if (stat(path.c_str(), &st2) != 0) {

      if (errno == ENOENT) {
        fprintf(stderr, "warning: path disappeared during scan: %s\n",
                path.c_str());
      } else if (errno == EACCES) {
        fprintf(stderr, "warning: permission denied while scanning: %s\n",
                path.c_str());
      } else {
        fprintf(stderr, "warning: stat failed for '%s': %s\n", path.c_str(),
                strerror(errno));
      }

      continue;
    }

    KEY k{};
    k.inode = st2.st_ino;
    k.dev = st_to_dev_sb(st2.st_dev);

    include_dir->push_back({k, value});
  }

  return 0;
}

int Parser::fill_exclusion_rules() {

  for (auto token : *tokens) {

    if (token.command == "E") {
      exclude_dir->insert({token.argument, 1});
    } else if (token.command == "EE") {
      userSpaceFilter->exclude_extension[token.argument] = 1;
    } else if (token.command == "ES") {
      userSpaceFilter->exclude_suffix.push_back(token.argument);
    } else if (token.command == "EP") {
      userSpaceFilter->exclude_prefix.push_back(token.argument);
    } else if (token.command == "P") {
      userSpaceFilter->exclude_pattern.push_back(std::regex(token.argument));
    } else if (token.command == "API_URL") {
      *api_url = token.argument;
    } else if (token.command == "API_HEADER") {
      auto [name, value] = split_once(token.argument, '=');
      api_header->push_back({name, value});
    }
  }

  return 0;
}

int Parser::compile() {

  int err;

  err = this->tokenize();
  if (err != 0) {
    fprintf(stderr, "Tokenization Failed \n");
    return -1;
  }

  err = this->syntaxValidation();
  if (err != 0) {
    fprintf(stderr, "Syntax Validation Failed \n");
    return -1;
  }

  err = this->semanticValidation();
  if (err != 0) {
    fprintf(stderr, "Semantic Validation Failed \n");
    return -1;
  }

  err = this->fill_exclusion_rules();
  if (err != 0) {
    fprintf(stderr, "Fill Exclusion Rules Failed \n");
    return -1;
  }

  for (auto token : *tokens) {
    if (token.command == "IF" || token.command == "D") {
      err = this->parseRule(token);
      if (err != 0) {
        fprintf(stderr, "Parse Rule Failed \n");
        return -1;
      }
    }
  }

  fprintf(stderr, "Total Entries in Inode Map: %ld\n", include_dir->size());
  fprintf(stderr, "Max size of Inode Map: %d\n", INODE_MAP_MAX_ENTRIES);

  return 0;
}
