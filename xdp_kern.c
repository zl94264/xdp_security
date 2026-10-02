#include <linux/bpf.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "xdp_shared.h"

#define QUEUE_NUM 4

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1FFF
#endif
#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef NEXTHDR_HOP
#define NEXTHDR_HOP 0
#define NEXTHDR_ROUTING 43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_AUTH 51
#define NEXTHDR_DEST 60
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct network_config);
} network_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POLICY_RULES);
    __type(key, __u32);
    __type(value, struct traffic_policy_rule);
} traffic_policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} tx_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, QUEUE_NUM);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map_in SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, QUEUE_NUM);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map_out SEC(".maps");

struct vlan_hdr_compat {
    __be16 tci;
    __be16 encapsulated_proto;
} __attribute__((packed));

struct arp_ipv4 {
    __u8 sha[ETH_ALEN];
    __u8 sip[4];
    __u8 tha[ETH_ALEN];
    __u8 tip[4];
} __attribute__((packed));

static __always_inline int fast_forward(const struct xdp_md *ctx,
                                        const struct network_config *cfg)
{
    __u32 key;
    if (ctx->ingress_ifindex == cfg->if_in_index)
        key = 1; /* tx_port_map[1] = outside */
    else if (ctx->ingress_ifindex == cfg->if_out_index)
        key = 0; /* tx_port_map[0] = inside */
    else
        return XDP_PASS;
    return bpf_redirect_map(&tx_port_map, key, XDP_PASS);
}

static __always_inline int prefix_match(const __u8 addr[16],
                                        const __u8 prefix[16], __u8 bits)
{
#pragma unroll
    for (int i = 0; i < 16; ++i) {
        int remaining = (int)bits - i * 8;
        if (remaining <= 0) break;
        __u8 mask = remaining >= 8 ? 0xffu : (__u8)(0xffu << (8 - remaining));
        if ((addr[i] & mask) != (prefix[i] & mask)) return 0;
    }
    return 1;
}

static __always_inline int policy_rule_matches(
    const struct traffic_policy_rule *rule, __u8 family, __u8 protocol,
    const __u8 src_addr[16], const __u8 dst_addr[16],
    __u16 src_port, __u16 dst_port)
{
    if (rule->family && rule->family != family) return 0;
    if (rule->protocol && rule->protocol != protocol) return 0;
    if (src_port < rule->src_port_start || src_port > rule->src_port_end ||
        dst_port < rule->dst_port_start || dst_port > rule->dst_port_end)
        return 0;
    if (!prefix_match(src_addr, rule->src_addr, rule->src_prefix_len) ||
        !prefix_match(dst_addr, rule->dst_addr, rule->dst_prefix_len))
        return 0;
    return 1;
}

static __always_inline int policy_requires_protection(
    const struct network_config *cfg, __u8 family, __u8 protocol,
    const __u8 src_addr[16], const __u8 dst_addr[16],
    __u16 src_port, __u16 dst_port)
{
    __u32 count = cfg->policy_count;
    if (count > MAX_POLICY_RULES) count = MAX_POLICY_RULES;

/*
 * Do not replace this with a bounded C loop.  Some deployed kernels predate
 * reliable bounded-loop verification and reject that bytecode as an infinite
 * loop.  Expanding the slots explicitly produces straight-line BPF on every
 * supported Clang version.
 */
#define CHECK_POLICY_SLOT(slot)                                               \
    {                                                                         \
        if (count > (slot)) {                                                  \
            __u32 key = (slot);                                                \
            const struct traffic_policy_rule *rule =                           \
                bpf_map_lookup_elem(&traffic_policy_map, &key);                \
            if (rule && policy_rule_matches(rule, family, protocol,            \
                    src_addr, dst_addr, src_port, dst_port))                    \
                return rule->action == POLICY_ACTION_PROTECT;                  \
        }                                                                      \
    }

    CHECK_POLICY_SLOT(0);
    CHECK_POLICY_SLOT(1);
    CHECK_POLICY_SLOT(2);
    CHECK_POLICY_SLOT(3);
    CHECK_POLICY_SLOT(4);
    CHECK_POLICY_SLOT(5);
    CHECK_POLICY_SLOT(6);
    CHECK_POLICY_SLOT(7);
    CHECK_POLICY_SLOT(8);
    CHECK_POLICY_SLOT(9);
    CHECK_POLICY_SLOT(10);
    CHECK_POLICY_SLOT(11);
    CHECK_POLICY_SLOT(12);
    CHECK_POLICY_SLOT(13);
    CHECK_POLICY_SLOT(14);
    CHECK_POLICY_SLOT(15);

#undef CHECK_POLICY_SLOT
    return cfg->default_policy_action == POLICY_ACTION_PROTECT;
}

static __always_inline int redirect_to_xsk(const struct xdp_md *ctx,
                                           const struct network_config *cfg)
{
    __u32 queue = ctx->rx_queue_index;
    if (queue >= QUEUE_NUM) return fast_forward(ctx, cfg);
    if (ctx->ingress_ifindex == cfg->if_in_index)
        return bpf_redirect_map(&xsks_map_in, queue, XDP_PASS);
    if (ctx->ingress_ifindex == cfg->if_out_index)
        return bpf_redirect_map(&xsks_map_out, queue, XDP_PASS);
    return XDP_PASS;
}

SEC("xdp")
int xdp_redirect_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 zero = 0;
    const struct network_config *cfg =
        bpf_map_lookup_elem(&network_config_map, &zero);
    if (!cfg) return XDP_PASS;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    __be16 eth_proto = eth->h_proto;
    void *cursor = eth + 1;

#pragma unroll
    for (int depth = 0; depth < 2; ++depth) {
        if (eth_proto != bpf_htons(ETH_P_8021Q) &&
            eth_proto != bpf_htons(ETH_P_8021AD))
            break;
        struct vlan_hdr_compat *vlan = cursor;
        if ((void *)(vlan + 1) > data_end) return fast_forward(ctx, cfg);
        eth_proto = vlan->encapsulated_proto;
        cursor = vlan + 1;
    }

    if (eth_proto == bpf_htons(ETH_P_ARP)) {
        struct arphdr *arp = cursor;
        if ((void *)(arp + 1) > data_end) return XDP_PASS;
        struct arp_ipv4 *arp_data = (void *)(arp + 1);
        if ((void *)(arp_data + 1) > data_end) return XDP_PASS;
        if (arp_data->tip[0] == cfg->arp_net[0] &&
            arp_data->tip[1] == cfg->arp_net[1] &&
            arp_data->tip[2] == cfg->arp_net[2])
            return XDP_PASS;
        return fast_forward(ctx, cfg);
    }

    __u8 family = 0;
    __u8 protocol = 0;
    __u8 src_addr[16] = {};
    __u8 dst_addr[16] = {};

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = cursor;
        if ((void *)(ip + 1) > data_end || ip->ihl < 5)
            return fast_forward(ctx, cfg);
        __u32 ip_hlen = (__u32)ip->ihl * 4;
        if ((void *)ip + ip_hlen > data_end) return fast_forward(ctx, cfg);
        if (ip->frag_off & bpf_htons(IP_MF | IP_OFFMASK))
            return fast_forward(ctx, cfg);
        family = 4;
        protocol = ip->protocol;
        __builtin_memcpy(src_addr, &ip->saddr, 4);
        __builtin_memcpy(dst_addr, &ip->daddr, 4);
        cursor = (void *)ip + ip_hlen;
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = cursor;
        if ((void *)(ip6 + 1) > data_end) return fast_forward(ctx, cfg);
        family = 6;
        protocol = ip6->nexthdr;
        __builtin_memcpy(src_addr, &ip6->saddr, 16);
        __builtin_memcpy(dst_addr, &ip6->daddr, 16);
        cursor = ip6 + 1;

#pragma unroll
        for (int depth = 0; depth < 4; ++depth) {
            if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) break;
            if (protocol == NEXTHDR_FRAGMENT)
                return fast_forward(ctx, cfg);
            if (protocol != NEXTHDR_HOP && protocol != NEXTHDR_ROUTING &&
                protocol != NEXTHDR_DEST && protocol != NEXTHDR_AUTH)
                return fast_forward(ctx, cfg);
            __u8 *ext = cursor;
            if ((void *)(ext + 2) > data_end) return fast_forward(ctx, cfg);
            __u32 ext_len = protocol == NEXTHDR_AUTH ?
                ((__u32)ext[1] + 2u) * 4u : ((__u32)ext[1] + 1u) * 8u;
            protocol = ext[0];
            if ((void *)ext + ext_len > data_end) return fast_forward(ctx, cfg);
            cursor = (void *)ext + ext_len;
        }
    } else {
        return fast_forward(ctx, cfg);
    }

    __u16 src_port;
    __u16 dst_port;
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = cursor;
        if ((void *)(tcp + 1) > data_end) return fast_forward(ctx, cfg);
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = cursor;
        if ((void *)(udp + 1) > data_end) return fast_forward(ctx, cfg);
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
        if ((dst_port == 67 && src_port == 68) ||
            (dst_port == 68 && src_port == 67))
            return fast_forward(ctx, cfg);
    } else {
        return fast_forward(ctx, cfg);
    }

    if (!policy_requires_protection(cfg, family, protocol, src_addr, dst_addr,
                                    src_port, dst_port))
        return fast_forward(ctx, cfg);
    return redirect_to_xsk(ctx, cfg);
}

char _license[] SEC("license") = "GPL";
