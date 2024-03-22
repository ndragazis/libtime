#!/bin/bash

GIT_ROOT_DIR=$(git rev-parse --show-toplevel)
LIB_PATH=${GIT_ROOT_DIR?}/libtime.so

LD_PRELOAD=${LIB_PATH?} SYMBOL=open /bin/bash
exit
