#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <csignal>
#include <cstdio>
#include <linux/bpf.h>
#include <unistd.h>

#include "event.hpp"
#include "logging.hpp"
#include "parser.hpp"
#include "processevent.hpp"
#include "shared_types.h"
#include "userspacefilter.hpp"

extern "C" {
#include "fentry_bpf.skel.h"
}
using namespace std;

ProcessEvent peventobj;
UserspaceFilter filter;
Logger logger;

int load_Inode_map(Parser *obj, fentry_bpf *skel) {

  __u32 size = (__u32)obj->include_dir->size();

  int mapfd = bpf_map__fd(skel->maps.InodeMap);

  if (mapfd < 0) {
    fprintf(stderr, "Failed to get map fd\n");
    return -1;
  }

  std::vector<KEY> keys;
  std::vector<VALUE> values;

  for (auto &[key, value] : *obj->include_dir) {

    keys.push_back(key);
    values.push_back(value);
  }

  int err =
      bpf_map_update_batch(mapfd, keys.data(), values.data(), &size, NULL);
  if (err) {
    fprintf(stderr, "Failed to update map\n");
    return -1;
  }
  fprintf(stderr, "Successfully updated map\n");
  return 0;
}

static volatile sig_atomic_t signal_received = 0;

void handle_signal(int) { signal_received = 1; }

int main(int argc, char **argv) {

  Events *events;
  thread producer_thread;
  thread consumer_thread;
  thread counter_thread;
  Parser *parser;
  int err;
  fentry_bpf *skel;

  fprintf(stderr, "Starting program\n");
  parser = new Parser("config.txt");
  err = parser->compile();
  if (err) {
    fprintf(stderr, "Failed to compile parser\n");
    return 1;
  }

  fprintf(stderr, "Successfully compiled parser\n");

  skel = fentry_bpf::open_and_load();

  if (!skel) {
    fprintf(stderr, "Failed to open skeleton\n");
    return 1;
  }

  fprintf(stderr, "Successfully opened skeleton\n");

  err = fentry_bpf::attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach skeleton\n");
    goto cleanup;
  }

  fprintf(stderr, "Successfully attached skeleton\n");

  load_Inode_map(parser, skel);
  fprintf(stderr, "Successfully loaded map\n");
  peventobj.initProcessEvent();
  fprintf(stderr, "Successfully initialized process event\n");
  filter.initFilter(parser);
  fprintf(stderr, "Successfully initialized filter\n");
  logger.init(parser);
  fprintf(stderr, "Successfully initialized logger\n");

  events = new Events(skel->maps.rb, bpf_map__fd(skel->maps.counter_map));

  printf("Successfully started!\n");
  printf("Run: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");

  signal(SIGINT, handle_signal);

  producer_thread = thread([&]() { events->producer(); });

  consumer_thread = thread([&]() { events->consumer(); });

  counter_thread = thread([&]() { events->counter_polling(); });

  while (!signal_received) {
    sleep(1);
  }

  events->stop();
  producer_thread.join();
  consumer_thread.join();
  if (counter_thread.joinable())
    counter_thread.join();
  delete events;
  delete parser;

cleanup:
  fentry_bpf::destroy(skel);
  printf("Successfully cleaned up\n");
  return err;
}