#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../common/common.h"

struct reuseport_config {
    __u8 s11_message_type;
    __u8 s10_message_type;
    __u8 allow_kernel_fallback;
    __u8 pad0;

    __u32 s11_pool_base;
    __u32 s11_pool_size;
    __u32 s10_pool_base;
    __u32 s10_pool_size;
    __u32 fallback_pool_base;
    __u32 fallback_pool_size;
};

struct gtpv2c_header_min {
    __u8 flags;
    __u8 message_type;
    __be16 length;
} __attribute__((packed));

struct pool_range {
    __u32 base;
    __u32 size;
};

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct reuseport_config);
} config_map SEC(".maps");

/*
 * Load the single runtime config object from config_map[0].
 */
static __always_inline const struct reuseport_config *
load_config(void)
{
    const __u32 key = UDP_GTP_GO_CONFIG_KEY;

    return bpf_map_lookup_elem(&config_map, &key);
}

/*
 * Return whether the pool definition is usable.
 */
static __always_inline int
pool_is_valid(const struct pool_range *pool)
{
    if (!pool)
        return 0;

    return pool->size > 0;
}

/*
 * Parse the GTPv2-C message type from the UDP payload.
 *
 * For SK_REUSEPORT on UDP, ctx->data starts at the UDP header.
 * The GTPv2-C header begins immediately after struct udphdr.
 */
static __always_inline int
parse_gtpv2_message_type(struct sk_reuseport_md *ctx, __u8 *message_type)
{
    void *data;
    void *data_end;
    struct udphdr *udp;
    struct gtpv2c_header_min *gtp;

    if (!ctx || !message_type)
        return -1;

    if (!udp_gtp_go_is_udp(ctx))
        return -1;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    udp = data;
    if (!udp_gtp_go_ptr_in_range(udp, data_end, sizeof(*udp)))
        return -1;

    gtp = (void *)(udp + 1);
    if (!udp_gtp_go_ptr_in_range(gtp, data_end, sizeof(*gtp)))
        return -1;

    *message_type = gtp->message_type;
    return 0;
}

/*
 * Classify a message type into a logical socket pool.
 */
static __always_inline struct pool_range
classify_pool(const struct reuseport_config *cfg, __u8 message_type)
{
    struct pool_range pool = {
        .base = cfg->fallback_pool_base,
        .size = cfg->fallback_pool_size,
    };

    if (message_type == cfg->s11_message_type) {
        pool.base = cfg->s11_pool_base;
        pool.size = cfg->s11_pool_size;
        return pool;
    }

    if (message_type == cfg->s10_message_type) {
        pool.base = cfg->s10_pool_base;
        pool.size = cfg->s10_pool_size;
        return pool;
    }

    return pool;
}

/*
 * Try to select a socket from the target pool using the kernel-provided flow hash.
 *
 * Return 0 on success and a negative value on failure.
 */
static __always_inline int
try_select_socket_from_pool(struct sk_reuseport_md *ctx,
                            const struct pool_range *pool)
{
    __u32 key;

    if (!ctx || !pool_is_valid(pool))
        return -1;

    key = pool->base + udp_gtp_go_hash_mod(ctx->hash, pool->size);

    return bpf_sk_select_reuseport(ctx, &sock_map, &key, 0);
}

/*
 * Return the fallback verdict when custom selection is unavailable.
 */
static __always_inline int
fallback_verdict(const struct reuseport_config *cfg)
{
    if (cfg && cfg->allow_kernel_fallback)
        return SK_PASS;

    return SK_DROP;
}

SEC("sk_reuseport")
int select_reuseport(struct sk_reuseport_md *ctx)
{
    const struct reuseport_config *cfg;
    struct pool_range pool;
    __u8 message_type = 0;
    int ret;

    cfg = load_config();
    if (!cfg)
        return SK_PASS;

    ret = parse_gtpv2_message_type(ctx, &message_type);
    if (ret < 0)
        return fallback_verdict(cfg);

    pool = classify_pool(cfg, message_type);
    if (!pool_is_valid(&pool))
        return fallback_verdict(cfg);

    ret = try_select_socket_from_pool(ctx, &pool);
    if (ret == 0)
        return SK_PASS;

    return fallback_verdict(cfg);
}

char LICENSE[] SEC("license") = "GPL";