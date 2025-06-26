#ifndef LIBINJECTOR_H
#define LIBINJECTOR_H

#include <sys/types.h>

pid_t findProcessPID(const char* processName);
int injectSharedLibrary(pid_t pid, const char* soPath);

#endif // LIBINJECTOR_H