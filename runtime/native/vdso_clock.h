// The clock page the VMM writes and the guest's vDSO reads.
#define FENDERS_CLOCK_PAGE 0x81000UL
#define FENDERS_VDSO_BASE 0x82000UL
#define FENDERS_VDSO_PAGES 4
#define FENDERS_CLOCKS 8
struct fenders_clock {
    uint64_t tsc_ref;          // guest TSC at which base_ns were read
    uint64_t mult;             // ns = (tsc delta * mult) >> shift
    uint32_t shift;
    uint32_t valid;            // bit per clock id the page can answer
    int64_t base_ns[FENDERS_CLOCKS];
};
