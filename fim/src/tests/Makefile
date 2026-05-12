CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -I../../include/user -I../../include -pthread -DCPPHTTPLIB_OPENSSL_SUPPORT
LDFLAGS = -lssl -lcrypto

TARGET_REGEX = test_regex.tst
TARGET_PARSER = test_parser.tst
SRCS_REGEX = test_regex.cpp ../user/parser.cpp ../user/userspacefilter.cpp
SRCS_PARSER = test_parser.cpp ../user/parser.cpp ../user/userspacefilter.cpp

all: $(TARGET_REGEX) $(TARGET_PARSER)

$(TARGET_REGEX): $(SRCS_REGEX)
	$(CXX) $(CXXFLAGS) -o $(TARGET_REGEX) $(SRCS_REGEX) $(LDFLAGS)

$(TARGET_PARSER): $(SRCS_PARSER)
	$(CXX) $(CXXFLAGS) -o $(TARGET_PARSER) $(SRCS_PARSER) $(LDFLAGS)

test: $(TARGET_REGEX) config.txt $(TARGET_PARSER) config_parser.txt
	./$(TARGET_REGEX)
	./$(TARGET_PARSER)

clean:
	rm -f $(TARGET_REGEX) $(TARGET_PARSER)

.PHONY: all test clean
