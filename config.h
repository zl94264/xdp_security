#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "xdp_shared.h"

#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

#define SEQ_STATE_PATH_MAX 256
#define MAX_KEY_DOMAINS 8

typedef struct {
    struct {
        char in_if[IF_NAMESIZE];
        char out_if[IF_NAMESIZE];
        int in_index;
        int out_index;
    } interface;

    struct {
        uint8_t arp_net[3];
        uint16_t heartbeat_port;
    } network;

    struct {
        uint16_t port;
        uint32_t interval_ms;
        uint32_t timeout_ms;
        uint32_t max_miss;
        char peer_ip[16];
    } heartbeat;

    struct {
        struct {
            uint8_t algo;
            uint8_t mode;
            uint8_t key_bits;
            uint8_t key[16];
            uint8_t iv[16];
        } sp_header;

        struct {
            uint8_t suite_id;
            uint16_t active_identifier;
            uint8_t key_domain_count;
            struct {
                uint16_t identifier;
                uint16_t rotation_span;
                uint8_t master_key[16];
            } key_domains[MAX_KEY_DOMAINS];
        } payload;
    } encryption;

    struct {
        uint32_t capacity;
        uint32_t udp_idle_timeout_ms;
        uint32_t tcp_idle_timeout_ms;
        uint32_t seq_reserve_size;
        char seq_state_file[SEQ_STATE_PATH_MAX];
    } flow_cache;

    struct {
        uint8_t default_action;
        uint16_t count;
        struct traffic_policy_rule rules[MAX_POLICY_RULES];
    } traffic_policy;

    struct {
        bool zero_copy;
    } data_plane;

    struct {
        bool socket_debug;
        bool heartbeat_debug;
    } debug;
} config_t;

extern config_t g_config;

int config_init(const char *config_file);
void config_cleanup(void);
const uint8_t *config_master_key_for_identifier(uint16_t identifier);
/* Return the next pre-provisioned KeyID epoch, or -1 at the end. */
int config_next_key_identifier(uint16_t current, uint16_t *next);
int config_select_security_context(uint8_t family, uint8_t protocol,
                                   const uint8_t src_addr[16],
                                   const uint8_t dst_addr[16],
                                   uint16_t src_port, uint16_t dst_port,
                                   uint8_t *action, uint8_t *suite_id,
                                   uint16_t *identifier);

#define IF_IN            (g_config.interface.in_if)
#define IF_OUT           (g_config.interface.out_if)
#define IF_IN_INDEX      (g_config.interface.in_index)
#define IF_OUT_INDEX     (g_config.interface.out_index)

#define ARP_NET_A        (g_config.network.arp_net[0])
#define ARP_NET_B        (g_config.network.arp_net[1])
#define ARP_NET_C        (g_config.network.arp_net[2])
#define HEARTBEAT_PORT   (g_config.network.heartbeat_port)

#define DEFAULT_PORT        (g_config.heartbeat.port)
#define DEFAULT_INTERVAL_MS (g_config.heartbeat.interval_ms)
#define DEFAULT_TIMEOUT_MS  (g_config.heartbeat.timeout_ms)
#define DEFAULT_MAX_MISS    (g_config.heartbeat.max_miss)
#define PEER_IP             (g_config.heartbeat.peer_ip)

#define SP_HEADER_ALGO       (g_config.encryption.sp_header.algo)
#define SP_HEADER_MODE       (g_config.encryption.sp_header.mode)
#define SP_HEADER_KEY_BITS   (g_config.encryption.sp_header.key_bits)
#define SP_HEADER_KEY        (g_config.encryption.sp_header.key)
#define SP_HEADER_IV         (g_config.encryption.sp_header.iv)

#define PAYLOAD_SUITE_ID     (g_config.encryption.payload.suite_id)
#define FLOW_IDENTIFIER      (g_config.encryption.payload.active_identifier)

#define FLOW_CACHE_CAPACITY       (g_config.flow_cache.capacity)
#define UDP_IDLE_TIMEOUT_MS       (g_config.flow_cache.udp_idle_timeout_ms)
#define TCP_IDLE_TIMEOUT_MS       (g_config.flow_cache.tcp_idle_timeout_ms)
#define SEQ_RESERVE_SIZE          (g_config.flow_cache.seq_reserve_size)
#define SEQ_STATE_FILE            (g_config.flow_cache.seq_state_file)

#define HEARTBEAT_DEBUG      (g_config.debug.heartbeat_debug)
#define SOCKET_DEBUG         (g_config.debug.socket_debug)

#endif /* CONFIG_H */
