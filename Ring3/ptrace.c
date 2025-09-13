#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <stdarg.h>


typedef long (*orig_ptrace_func_t)(enum __ptrace_request request, ...);

long ptrace(enum __ptrace_request request, ...) {
    fprintf(stderr, "[HOOK] request blocked %d\n", request);

    
    errno = EPERM;
    return -1;
}


