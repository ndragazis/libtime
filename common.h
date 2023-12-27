#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>

#define ensure(condition) \
        do { \
                if (!(condition)) { \
                        fprintf(stderr, "Assertion failed: %s\n",\
                                #condition); \
                        abort(); \
                } \
        } while (0)

#endif  /* COMMON_H */
