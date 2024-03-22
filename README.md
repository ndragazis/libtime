# libtime

:warning: DISCLAIMER :warning:: There are some amazing production-level
tools out there for doing dynamic user-level tracing (e.g., LTTng,
uprobes). libtime is nothing but a toy project. It was meant to help me
explore the ELF machinery.

## Introduction

libtime is a shared library that can be used to measure latencies of
function calls in your programs.

## Rationale

Performance optimizations often require measuring function call
latencies. The way I often used to tackle this is by injecting some
source code that measures the execution time via ``clock_gettime(2)``
and prints the latency to standard output. Then, optionally one can
parse the output with a script to get some latency statistics (min, max,
average, percentiles, etc.). This is probably the easiest thing one can
do.

The problem with this solution is that it is time consuming. You have to
change the source code and re-compile the code for each code path that
you want to measure. And if the software is running in a containerized
environment e.g., in Kubernetes, you have to build a new image, upload
it to a container registry, change the image tag in the manifest(s) and
re-apply the manifest(s).

So, the logical question that comes at this point is: Can we measure
latencies at runtime, i.e., without changing and re-compiling the source
code?

libtime offers one way to accomplish that for **dynamically linked** ELF
objects. libtime works by hijacking function calls at runtime via the
GOT segments. The GOT is where the dynamic linker keeps the addresses of
the symbols for which there are undefined symbol references.

## How to use

Preload the library along with your executables via the ``LD_PRELOAD``
env var. This instructs the GNU dynamic linker to load this library and
use it for symbol resolution.

To define a symbol name that you want to measure, use the ``SYMBOL`` env
var. This env var is parsed by libtime.

To enable debug mode, use the ``DEBUG`` env var.

The library will print a log message in standard output for each call to
the specified symbol.

Here is an example:
```
$ SYMBOL=memcpy LD_PRELOAD=./libtime.so ls /home
Waited for memcpy for 121 nsec
Waited for memcpy for 83 nsec
Waited for memcpy for 161 nsec
Waited for memcpy for 91 nsec
Waited for memcpy for 54 nsec
Waited for memcpy for 180 nsec
nikos
```

## Limitations

Currently, libtime has some limitations:

1. It cannot measure functions that are internal to libraries or
   executables. The references to these functions are fixed offsets that
   are resolved at static linking. So, libtime can be used only for
   dynamic symbol references, i.e., references that are resolved at
   runtime by the dynamic linker. Dynamic symbol references are
   inter-object references, that is references from executables to
   shared libraries or references from shared libraries to other shared
   libraries.

2. It only works on x86_64 architectures and binaries that adhere to
   the System V x86_64 ABI.

3. It does not support recursive functions.

## References and Useful Links

* ELF Spec: https://refspecs.linuxfoundation.org/elf/elf.pdf
