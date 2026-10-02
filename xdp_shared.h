#ifndef XDP_SHARED_H
#define XDP_SHARED_H

#include <linux/types.h>

/*
 * Keep the policy table small enough for full compile-time unrolling.  This
 * avoids relying on bounded-loop support in older BPF verifiers while still
 * leaving ample room for the offline rules used by the gateway.
 */
#define MAX_POLICY_RULES 16
#define POLICY_ACTION_BYPASS  0u
#define POLICY_ACTION_PROTECT 1u

/* Shared verbatim between the BPF program and user-space loader. */
struct network_config {
    __u8 arp_net[3];
    __u8 default_policy_action;
    __u16 policy_count;
    __u16 reserved;
    __u32 if_in_index;
    __u32 if_out_index;
};

struct traffic_policy_rule {
    __u8 family;          /* 0=any, 4=IPv4, 6=IPv6 */
    __u8 protocol;        /* 0=any, otherwise IPPROTO_* */
    __u8 action;          /* POLICY_ACTION_* */
    __u8 suite_id;
    __u8 src_prefix_len;
    __u8 dst_prefix_len;
    __u16 identifier;
    __u16 src_port_start; /* host byte order in the local BPF map */
    __u16 src_port_end;
    __u16 dst_port_start;
    __u16 dst_port_end;
    __u8 src_addr[16];
    __u8 dst_addr[16];
};

#endif /* XDP_SHARED_H */
