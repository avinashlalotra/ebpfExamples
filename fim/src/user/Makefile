INCLUDE_DIR = ../../include/user
INCLUDE = ../../include
PROG_NAME = fentry

CXX = g++
CXXFLAGS = -std=c++20 -I$(INCLUDE_DIR) -I$(INCLUDE) -pthread
LDFLAGS = -lbpf -pthread

# Sources that are shared (no main here)
USER_SRCS = logging.cpp event.cpp parser.cpp userspacefilter.cpp  processevent.cpp daemon.cpp
USER_OBJS = $(USER_SRCS:.cpp=.o)

MAIN_SRC = main.cpp 
MAIN_OBJ = $(MAIN_SRC:.cpp=.o)

CONFIG_DEBUG_TOKENS = y
CONFIG_DEBUG_PARSER = y
CONFIG_DEBUG_USERSPACE_FILTER = y

ifeq ($(CONFIG_RENAME),y)
CXXFLAGS += -DCONFIG_RENAME
endif

ifeq ($(CONFIG_DEBUG_TOKENS),y)
CXXFLAGS += -DDEBUG_TOKENS
endif

ifeq ($(CONFIG_DEBUG_PARSER),y)
CXXFLAGS += -DDEBUG_PARSER
endif

ifeq ($(CONFIG_DEBUG_USERSPACE_FILTER),y)
CXXFLAGS += -DDEBUG_USERSPACE_FILTER
endif

CXXFLAGS += -DCPPHTTPLIB_OPENSSL_SUPPORT

LDFLAGS += -lssl -lcrypto

all: USER_BUILD

%.o: %.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS)

USER_BUILD: $(MAIN_OBJ) $(USER_OBJS)
	$(CXX) $(MAIN_OBJ) $(USER_OBJS) -o ../../$(PROG_NAME) $(LDFLAGS)

clean:
	rm -f ../../$(PROG_NAME)
	rm -f tests
	rm -f *.o



# Test build
TEST_SRCS = tests.cpp
TEST_OBJS = $(TEST_SRCS:.cpp=.o)

tests: $(TEST_OBJS) $(USER_OBJS)
	$(CXX) $(TEST_OBJS) $(USER_OBJS) -o tests $(LDFLAGS)