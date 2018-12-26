#ifndef timingH
#define timingH

#include <time.h>

#ifdef _MSC_VER
#define CLOCK_MONOTONIC 0
int clock_gettime(int, struct timespec *spec);     //C-file part
#endif

#endif