// The guest's vDSO: clock_gettime for the clocks the TSC can answer, read in
// the guest without a VM exit. musl calls __vdso_clock_gettime when the VMM
// passes this image as AT_SYSINFO_EHDR. The VMM fills the read-only clock
// page (FENDERS_CLOCK_PAGE) before the guest runs and keeps every vCPU's TSC
// on vCPU 0's offset; a clock it cannot answer, or a page it marked invalid,
// takes the ordinary syscall.
#include <stdint.h>
#include "vdso_clock.h"

static long clock_syscall(long clock, void *ts) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(228L), "D"(clock), "S"(ts) : "rcx", "r11", "memory");
    return ret;
}

struct timespec_abi { int64_t tv_sec; int64_t tv_nsec; };

int __vdso_clock_gettime(int clock, struct timespec_abi *ts) {
    const volatile struct fenders_clock *page = (const volatile struct fenders_clock *)FENDERS_CLOCK_PAGE;
    if (clock >= 0 && clock < FENDERS_CLOCKS && (page->valid & (1u << clock))) {
        uint32_t lo, hi;
        __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
        int64_t delta = (int64_t)((((uint64_t)hi << 32) | lo) - page->tsc_ref);
        if (delta < 0) delta = 0;
        int64_t ns = page->base_ns[clock] +
            (int64_t)(((unsigned __int128)(uint64_t)delta * page->mult) >> page->shift);
        ts->tv_sec = ns / 1000000000;
        ts->tv_nsec = ns % 1000000000;
        return 0;
    }
    return (int)clock_syscall(clock, ts);
}
int clock_gettime(int, struct timespec_abi *) __attribute__((weak, alias("__vdso_clock_gettime")));
