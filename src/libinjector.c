#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <sys/user.h>
#include "libinjector.h"

pid_t findProcessPID(const char* processName) {
    DIR* d = opendir("/proc");
    if (!d) return -1;

    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR) continue;
        pid_t pid = atoi(e->d_name);
        if (pid <= 0) continue;

        char buf[512];
        snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
        FILE* f = fopen(buf, "r");
        if (!f) continue;

        fread(buf, 1, sizeof(buf), f);
        fclose(f);

        if (strstr(buf, processName)) {
            closedir(d);
            return pid;
        }
    }
    closedir(d);
    return -1;
}

int injectSharedLibrary(pid_t pid, const char* soPath) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) return 0;
    waitpid(pid, NULL, 0);

    size_t len = strlen(soPath) + 1;

    void* handle = dlopen("libc.so.6", RTLD_LAZY);
    void* mmapAddr = dlsym(handle, "mmap");
    dlclose(handle);
    if (!mmapAddr) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 0;
    }

    struct user_regs_struct regs, backup;
    ptrace(PTRACE_GETREGS, pid, NULL, &backup);
    regs = backup;

    regs.rdi = 0;
    regs.rsi = (len + 0x1000) & ~0xFFF;
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE;
    regs.r8 = -1;
    regs.r9 = 0;
    regs.rax = (unsigned long)mmapAddr;
    regs.rip = (unsigned long)mmapAddr;

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, NULL, 0);

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    void* remoteMem = (void*)regs.rax;

    struct iovec local = { (void*)soPath, len };
    struct iovec remote = { remoteMem, len };
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 0;
    }

    handle = dlopen("libdl.so.2", RTLD_LAZY);
    void* dlopenAddr = dlsym(handle, "dlopen");
    dlclose(handle);
    if (!dlopenAddr) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 0;
    }

    regs = backup;
    regs.rdi = (unsigned long)remoteMem;
    regs.rsi = RTLD_NOW | RTLD_GLOBAL;
    regs.rax = (unsigned long)dlopenAddr;
    regs.rip = (unsigned long)dlopenAddr;

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, NULL, 0);

    ptrace(PTRACE_SETREGS, pid, NULL, &backup);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 1;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <process-name> <path-to-so>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char* procName = argv[1];
    const char* soPath = argv[2];

    pid_t pid = findProcessPID(procName);
    if (pid == -1) {
        fprintf(stderr, "Error: process '%s' not found\n", procName);
        return EXIT_FAILURE;
    }

    if (!injectSharedLibrary(pid, soPath)) {
        fprintf(stderr, "Injection failed.\n");
        return EXIT_FAILURE;
    }

    printf("Injected '%s' into process '%s' (PID %d)\n", soPath, procName, pid);
    return EXIT_SUCCESS;
}