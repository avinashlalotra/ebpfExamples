#include "event.hpp"
#include "logging.hpp"
#include "payload.hpp"
#include "processevent.hpp"
#include "userspacefilter.hpp"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

int callback(void *ctx, void *data, size_t size);
void print_event(EVENT *event);
extern Payload process_event(EVENT *event);
extern ProcessEvent peventobj;
extern UserspaceFilter filter;
extern Logger logger;

Events::Events(const struct bpf_map *map, int counter_map_fd)
    : counter_map_fd(counter_map_fd) {

  int fd = bpf_map__fd(map);
  if (fd < 0) {
    fprintf(stderr, "Failed to get map fd: %d\n", fd);
    return;
  }

  rb = ring_buffer__new(fd, callback, this, NULL);
  if (!rb) {
    fprintf(stderr, "Failed to create ring buffer\n");
    return;
  }
}

Events::~Events() {
  if (rb)
    ring_buffer__free(rb);
}

void Events::producer() {
  while (!stop_flag) {

    int ret = ring_buffer__poll(rb, 100); // blocking

    if (ret < 0) {
      fprintf(stderr, "ring_buffer__poll error: %d\n", ret);
      break;
    }
  }
}

void Events::consumer() {

  Payload p;
  while (!stop_flag) {

    std::unique_lock<std::mutex> lock(queue_mutex);

    queue_cv.wait(lock, [this] { return stop_flag || !event_queue.empty(); });

    if (stop_flag && event_queue.empty())
      return;

    EVENT event = event_queue.front();
    event_queue.pop();

    lock.unlock();

    if (filter.filterEvent(&event)) {
      printf("Event filtered %s\n", event.filepath);
      continue;
    }

    p = peventobj.Process(&event);

    peventobj.print_event(&p);

    logger.log(&p);
  }
}

void Events::stop() {
  stop_flag = true;
  queue_cv.notify_all(); // wake consumer
}

void Events::counter_polling() {
  __u32 key = 0;
  __u64 value = 0;
  while (!stop_flag) {
    if (bpf_map_lookup_elem(counter_map_fd, &key, &value) == 0) {
      if (value > 0) {
        printf("Global counter: %llu\n", value);
      }
    } else {
      // printf("Failed to read global counter\n");
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

// push data to queue
int callback(void *ctx, void *data, size_t size) {

  EVENT *event = (EVENT *)data;
  Events *events = (Events *)ctx;

  {
    std::lock_guard<std::mutex> lock(events->queue_mutex);
    events->event_queue.push(*event);
  }

  events->queue_cv.notify_one();

  return 0;
}
