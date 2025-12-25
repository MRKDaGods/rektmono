#pragma once

#ifndef DISABLE_LOGGING
#include <cstdio>
#define LOG(msg, ...) printf("[Loader] " msg "\n", ##__VA_ARGS__)
#else
#define LOG(msg, ...)
#endif