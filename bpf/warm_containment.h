#ifndef EPHEM_WARM_CONTAINMENT_H
#define EPHEM_WARM_CONTAINMENT_H

/* This ABI is shared by the eBPF object and the optional privileged loader.
 * The includer supplies __u32 and __u64 (Linux UAPI types). */
#define EPHEM_WARM_BASELINE 1U
#define EPHEM_WARM_WORKER 2U
#define EPHEM_WARM_DENIED_EXEC (1U << 0)
#define EPHEM_WARM_DENIED_NETWORK (1U << 1)
#define EPHEM_WARM_DENIED_FD (1U << 2)
#define EPHEM_WARM_DENIED_FORK (1U << 3)

struct ephem_warm_task {
    __u64 generation;
    __u32 kind;
    __u32 depth;
};

struct ephem_warm_generation {
    __u32 violations;
    __u32 reserved;
};

#endif
