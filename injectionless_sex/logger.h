#pragma once

#ifndef DISABLE_LOGGING
#include <cstdio>
#define LOG(msg, ...) printf("[m] " msg "\n", ##__VA_ARGS__)
#else
#define LOG(msg, ...)
#endif

#ifndef DISABLE_VERBOSE_LOGGING
#include <cstdio>
#define VLOG(msg, ...) printf("[v] " msg "\n", ##__VA_ARGS__)
#else
#define VLOG(msg, ...)
#endif