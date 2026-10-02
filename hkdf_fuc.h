#ifndef HKDF_FUC_H
#define HKDF_FUC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM4_KEY_LENGTH 16
#define SM4_IV_LENGTH  16
#define FLOW_ADDR_LENGTH 16

#define HKDF_SUCCESS        0
#define HKDF_ERROR_INPUT   -1
#define HKDF_ERROR_EXTRACT -2
#define HKDF_ERROR_EXPAND  -3

/* Packet tuple fields are kept in network byte order. */
struct five_tuple {
    uint8_t  family;
    uint8_t  protocol;
    uint8_t  src_addr[FLOW_ADDR_LENGTH];
    uint8_t  dst_addr[FLOW_ADDR_LENGTH];
    uint16_t src_port;
    uint16_t dst_port;
} __attribute__((packed));

/* Direction-neutral flow identifier. Direction is carried separately. */
struct flow_id {
    uint8_t  family;
    uint8_t  protocol;
    uint8_t  endpoint_a_addr[FLOW_ADDR_LENGTH];
    uint16_t endpoint_a_port;
    uint8_t  endpoint_b_addr[FLOW_ADDR_LENGTH];
    uint16_t endpoint_b_port;
} __attribute__((packed));

int canonicalize_five_tuple(const struct five_tuple *tuple,
                            struct flow_id *fid, uint8_t *direction);

/*
 * K_flow = KDF(K_master, fid || identifier || "DATA")
 * K_IV   = KDF(K_master, fid || identifier || "IV")
 *
 * Direction is deliberately excluded from these two per-flow keys. It is
 * included in the per-packet IV input, exactly as in Equations (3)-(5).
 */
int derive_flow_keys(const struct flow_id *fid, uint16_t identifier,
                     uint8_t direction, unsigned char *flow_key_out,
                     unsigned char *iv_key_out);

/* IV = PRF_K_IV(fid || identifier || Seq || dir), truncated to 16 bytes. */
int derive_packet_iv(const struct flow_id *fid, uint16_t identifier,
                     uint8_t direction, uint32_t seq,
                     const unsigned char *iv_key,
                     unsigned char *iv_out);

/* Backward-compatible helper; new packet processing uses derive_flow_keys. */
int derive_key_from_five_tuple(const struct five_tuple *tuple,
                               unsigned char *key_out);

#ifdef __cplusplus
}
#endif

#endif /* HKDF_FUC_H */
