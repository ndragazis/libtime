#!/bin/bash

GIT_ROOT_DIR=$(git rev-parse --show-toplevel)
LIB_PATH=${GIT_ROOT_DIR?}/libtime.so

LD_PRELOAD=${LIB_PATH?} SYMBOL=opendir ls
#LD_PRELOAD=${LIB_PATH?} SYMBOL=fread ls
#LD_PRELOAD=${LIB_PATH?} SYMBOL=fwrite ls
#LD_PRELOAD=${LIB_PATH?} SYMBOL=malloc ls
#LD_PRELOAD=${LIB_PATH?} SYMBOL=prctl DEBUG=1 ls
#LD_PRELOAD=${LIB_PATH?} SYMBOL=prctl ls
#LD_PRELOAD=${LIB_PATH?} SYMBOL=puts DEBUG=1 ls
#LD_PRELOAD=${LIB_PATH?} SYMBOL=__tls_get_addr DEBUG=1 ls
#LD_PRELOAD=${LIB_PATH?} SYMBOL=memcpy DEBUG=1 ls
