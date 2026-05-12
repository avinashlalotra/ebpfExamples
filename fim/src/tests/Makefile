CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -I../../include/user -I../../include -pthread -DCPPHTTPLIB_OPENSSL_SUPPORT
LDFLAGS = -lssl -lcrypto

TARGET_REGEX = test_regex.tst
TARGET_PARSER = test_parser.tst
TARGET_PAYLOAD = test_payload.tst
SRCS_REGEX = test_regex.cpp ../user/parser.cpp ../user/userspacefilter.cpp
SRCS_PARSER = test_parser.cpp ../user/parser.cpp ../user/userspacefilter.cpp
SRCS_PAYLOAD = test_payload.cpp

all: $(TARGET_REGEX) $(TARGET_PARSER) $(TARGET_PAYLOAD)

$(TARGET_REGEX): $(SRCS_REGEX)
	$(CXX) $(CXXFLAGS) -o $(TARGET_REGEX) $(SRCS_REGEX) $(LDFLAGS)

$(TARGET_PARSER): $(SRCS_PARSER)
	$(CXX) $(CXXFLAGS) -o $(TARGET_PARSER) $(SRCS_PARSER) $(LDFLAGS)

$(TARGET_PAYLOAD): $(SRCS_PAYLOAD)
	$(CXX) $(CXXFLAGS) -o $(TARGET_PAYLOAD) $(SRCS_PAYLOAD) $(LDFLAGS)

test: $(TARGET_REGEX) config.txt $(TARGET_PARSER) config_parser.txt $(TARGET_PAYLOAD)
	./$(TARGET_REGEX)
	./$(TARGET_PARSER)
	./$(TARGET_PAYLOAD)

clean:
	rm -f $(TARGET_REGEX) $(TARGET_PARSER) $(TARGET_PAYLOAD)

.PHONY: all test clean
