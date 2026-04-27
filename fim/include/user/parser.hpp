#ifndef PARSER_H
#define PARSER_H

#include "shared_types.h"
#include "types.hpp"
#include <memory>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/* ---------------------------------------------------------
   Token
---------------------------------------------------------*/
class Token {
public:
  Token(int lineNumber, const std::string &command,
        const std::string &argument);
#ifdef DEBUG_TOKENS
  void printToken() const;
#endif

public:
  int lineNumber;
  std::string command;
  std::string argument;
};

/* ---------------------------------------------------------
   Parser
---------------------------------------------------------*/
class Parser {

public:
  Parser(const std::string &policyFilePath);
  ~Parser();

  void parsePolicyFile();

  user_space_filter *getUserSpaceFilter();
  const std::vector<std::string> &getApiUrl() const;
  const std::vector<std::pair<std::string, std::string>> &getApiHeader() const;
  const std::unordered_map<KEY, VALUE> &getIncludeDir() const;
#ifdef DEBUG_PARSER
  void printParser() const;
#endif

public:
  std::string policyFilePath;

  std::vector<Token> *tokens;

  /* API configuration */
  std::string *api_url;
  int api_port;
  std::vector<std::pair<std::string, std::string>> *api_header;

  /* exclusion rules */
  std::unordered_map<std::string, int> *exclude_dir;
  user_space_filter *userSpaceFilter;

  /* inclusion rules */
  std::vector<std::pair<KEY, VALUE>> *include_dir;

  /* parser pipeline */
  int tokenize();
  int syntaxValidation();
  int semanticValidation();
  int compile();
  int parseRule(const Token &token);
  int fill_exclusion_rules();
};

#endif