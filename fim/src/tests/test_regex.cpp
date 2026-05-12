#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "parser.hpp"
#include "shared_types.h"
#include "userspacefilter.hpp"

void test_regex_matching() {
  // Construct parser pointing to config.txt in the same directory
  Parser parser("config.txt");

  // Compile triggers tokenization, validation, and filling exclusion rules
  int err = parser.compile();
  if (err != 0) {
    std::cerr << "Parser compilation failed. Please ensure config.txt exists "
                 "and is valid.\n";
    assert(err == 0);
  }

  // Initialize UserspaceFilter using the parser
  UserspaceFilter filter;
  filter.initFilter(&parser);

  // Test cases: pair of <filename, expected_match_result>
  // true means the pattern matched and the event is filtered out (excluded)
  std::vector<std::pair<std::string, bool>> test_cases = {
      // 1. P: \.lesshs[a-zA-Z0-9]+$
      {"/root/.lesshst", true},
      {"/home/user/.lesshs123", true},
      {"/home/user/.lesshs", false}, // missing alphanumeric after

      // 2. P: \.[0-9]+$
      {"/var/log/syslog.1", true},
      {"/var/log/syslog.10", true},
      {"/var/log/syslog", false},
      {"/var/log/syslog.gz", false},

      // 3. P: \.bash_history(-\d+\.tmp|\.pts_\d+|\.ttymxc\d+)?$
      {"/home/user/.bash_history", true},
      {"/home/user/.bash_history-123.tmp", true},
      {"/home/user/.bash_history.pts_1", true},
      {"/home/user/.bash_history.ttymxc1", true},
      {"/home/user/.bash_history_old", false},
      {"/home/user/.bash_history-abc.tmp", false},

      // 4 . p: [0-9]
      {"/home/user/1234", true}};

  size_t passed = 0;
  for (const auto &test_case : test_cases) {
    // Construct dummy EVENT
    EVENT eventObj{};
    std::strncpy(eventObj.filepath, test_case.first.c_str(), MAX_PATH_LEN - 1);
    eventObj.filepath[MAX_PATH_LEN - 1] = '\0';

    // Use filterEvent
    bool matched = filter.filterEvent(&eventObj);

    if (matched == test_case.second) {
      passed++;
    } else {
      std::cerr << "Test failed for: " << test_case.first
                << " (Expected: " << test_case.second << ", Got: " << matched
                << ")\n";
    }
  }

  std::cout << "Regex Test: " << passed << "/" << test_cases.size()
            << " passed.\n";
  assert(passed == test_cases.size());
}

int main() {
  std::cout << "Running regex pattern matching tests with UserspaceFilter...\n";
  test_regex_matching();
  return 0;
}
