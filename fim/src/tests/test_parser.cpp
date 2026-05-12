#include <cassert>
#include <iostream>
#include <string>
#include <cstdlib>

#include "parser.hpp"
#include "shared_types.h"

void setup_test_env() {
    system("mkdir -p /tmp/test_fim_include/sub");
    system("mkdir -p /tmp/test_fim_exclude");
    system("touch /tmp/test_fim_exclude/force.txt");
}

void teardown_test_env() {
    system("rm -rf /tmp/test_fim_include");
    system("rm -rf /tmp/test_fim_exclude");
}

void test_parser() {
    setup_test_env();

    Parser parser("config_parser.txt");
    int err = parser.compile();
    if (err != 0) {
        std::cerr << "Parser compilation failed. Please ensure config_parser.txt exists.\n";
        assert(err == 0);
    }

    // 1. Check API Configuration
    assert(*parser.api_url == "https://api.example.com");
    assert(parser.api_port == 8080);
    assert(parser.api_header->size() == 2);
    assert((*parser.api_header)[0].first == "Authorization");
    assert((*parser.api_header)[0].second == "Bearer abc123");
    assert((*parser.api_header)[1].first == "Content-Type");
    assert((*parser.api_header)[1].second == "application/json");

    // 2. Check Directories Exclusion
    assert(parser.exclude_dir->find("/tmp/test_fim_exclude") != parser.exclude_dir->end());

    // 3. Check Inclusion (D and IF)
    // We can't directly check the paths because include_dir stores INODEs.
    // However, if size is at least 3, we know it populated successfully.
    assert(parser.include_dir->size() >= 3);

    // 4. Check user space filter rules
    auto filter = parser.getUserSpaceFilter();
    assert(filter->exclude_extension.find("log") != filter->exclude_extension.end());
    
    bool found_es = false;
    for (const auto& suffix : filter->exclude_suffix) {
        if (suffix == "_backup") found_es = true;
    }
    assert(found_es);

    bool found_ep = false;
    for (const auto& prefix : filter->exclude_prefix) {
        if (prefix == "tmp_") found_ep = true;
    }
    assert(found_ep);

    assert(filter->exclude_pattern.size() == 1);

    std::cout << "Parser tests passed successfully.\n";
    teardown_test_env();
}

int main() {
    std::cout << "Running parser tests...\n";
    test_parser();
    return 0;
}
