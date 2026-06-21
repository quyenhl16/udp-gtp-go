#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../common/common.h"

#define SELECTION_MODE_FLOW_HASH 0
#define SELECTION_MODE_GTP_SEQUENCE 1
#define SELECTION_MODE_GTP_TEID 2
#define GTPV2_FLAG_TEID 0x08

struct reuseport_config {
    __u8 s11_message_type;
    __u8 s10_message_type;
    __u8 allow_kernel_fallback;
    __u8 selection_mode;

    __u32 s11_pool_base;
    __u32 s11_pool_size;
    __u32 s10_pool_base;
    __u32 s10_pool_size;
    __u32 fallback_pool_base;
    __u32 fallback_pool_size;
};

struct packet_meta {
    __u8 message_type;
    __u32 teid;
    __u32 sequence;
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
parse_gtpv2_meta(struct sk_reuseport_md *ctx, struct packet_meta *meta)
{
    void *data;
    void *data_end;
    struct udphdr *udp;
    __u8 *gtp;
    __u8 flags;
    __u32 seq_offset;

    if (!ctx || !meta)
        return -1;

    if (!udp_gtp_go_is_udp(ctx))
        return -1;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    udp = data;
    if (!udp_gtp_go_ptr_in_range(udp, data_end, sizeof(*udp)))
        return -1;

    gtp = (void *)(udp + 1);

    if (!udp_gtp_go_ptr_in_range(gtp, data_end, 8))
        return -1;

    flags = gtp[0];

    meta->message_type = gtp[1];

    if (flags & GTPV2_FLAG_TEID) {
        if (!udp_gtp_go_ptr_in_range(gtp, data_end, 12))
            return -1;

        meta->teid = ((__u32)gtp[4] << 24) |
                     ((__u32)gtp[5] << 16) |
                     ((__u32)gtp[6] << 8) |
                     ((__u32)gtp[7]);
        seq_offset = 8;
    } else {
        meta->teid = 0;
        seq_offset = 4;
    }

    meta->sequence = ((__u32)gtp[seq_offset] << 16) |
                     ((__u32)gtp[seq_offset + 1] << 8) |
                     ((__u32)gtp[seq_offset + 2]);

    return 0;
}

static __always_inline __u32
selection_seed(const struct reuseport_config *cfg,
               const struct packet_meta *meta,
               struct sk_reuseport_md *ctx)
{
    if (!cfg || !meta || !ctx)
        return 0;

    if (cfg->selection_mode == SELECTION_MODE_GTP_SEQUENCE && meta->sequence != 0)
        return meta->sequence;

    if (cfg->selection_mode == SELECTION_MODE_GTP_TEID && meta->teid != 0)
        return meta->teid;

    return ctx->hash;
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
                            const struct pool_range *pool,
                            __u32 seed)
{
    __u32 key;

    if (!ctx || !pool_is_valid(pool))
        return -1;

    key = pool->base + udp_gtp_go_hash_mod(seed, pool->size);

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
    struct packet_meta meta = {};
    struct pool_range pool;
    __u32 seed;
    int ret;

    cfg = load_config();
    if (!cfg)
        return SK_PASS;

    ret = parse_gtpv2_meta(ctx, &meta);
    if (ret < 0)
        return fallback_verdict(cfg);

    pool = classify_pool(cfg, meta.message_type);
    if (!pool_is_valid(&pool))
        return fallback_verdict(cfg);

    seed = selection_seed(cfg, &meta, ctx);

    ret = try_select_socket_from_pool(ctx, &pool, seed);
    if (ret == 0)
        return SK_PASS;

    return fallback_verdict(cfg);
}

char LICENSE[] SEC("license") = "GPL";
