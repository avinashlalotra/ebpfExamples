#include "parser.hpp"
#include <cstdio>

int main() {

  Parser parser("../../config.txt");
  int err = parser.compile();
  //   if (err != 0) {
  //     fprintf(stderr, "Parser failed\n");
  //     return -1;
  //   }

#ifdef DEBUG_PARSER
  parser.printParser();
#endif

  return 0;
}