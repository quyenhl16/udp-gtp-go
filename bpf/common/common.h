#ifndef UDP_GTP_GO_BPF_COMMON_H_
#define UDP_GTP_GO_BPF_COMMON_H_

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define UDP_GTP_GO_CONFIG_KEY 0

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

/*
 * Check whether a fixed-size object starting at ptr is fully inside [ptr, end).
 */
static __always_inline int
udp_gtp_go_ptr_in_range(const void *ptr, const void *end, __u64 size)
{
    return (__u64)ptr + size <= (__u64)end;
}

/*
 * Return value % size and guard against division by zero.
 */
static __always_inline __u32
udp_gtp_go_hash_mod(__u32 value, __u32 size)
{
    if (size == 0)
        return 0;

    return value % size;
}

/*
 * Return whether the current reuseport context carries UDP traffic.
 */
static __always_inline int
udp_gtp_go_is_udp(const struct sk_reuseport_md *ctx)
{
    if (!ctx)
        return 0;

    return ctx->ip_protocol == IPPROTO_UDP;
}

#endif /* UDP_GTP_GO_BPF_COMMON_H_ */