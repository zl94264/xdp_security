#ifndef SP_HEADER_H
#define SP_HEADER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SP_PROTO_VERSION       0x01u
#define SP_SUITE_SM4_CBC_128   0x01u

/* Algorithm identifiers retained for configuration compatibility. */
#define SP_ALGO_PLAINTEXT 0x00u
#define SP_ALGO_SM1       0x01u
#define SP_ALGO_SM2       0x02u
#define SP_ALGO_SM3       0x03u
#define SP_ALGO_SM4       0x04u

#define SP_MODE_ECB       0x01u
#define SP_MODE_CBC       0x02u
#define SP_MODE_CFB       0x03u
#define SP_MODE_OFB       0x04u
#define SP_MODE_CTR       0x05u

#define SP_KEY_64BIT      0x01u
#define SP_KEY_128BIT     0x02u
#define SP_KEY_192BIT     0x03u
#define SP_KEY_256BIT     0x04u

/*
 * Wire layout from Fig. 4 of the paper (exactly 8 bytes):
 *
 *   proto_no(1 B) | suite_id(1 B) | identifier(2 B) | seq(4 B)
 *
 * Multi-byte fields are stored in network byte order. Seq is an input to IV
 * derivation and is never used as the IV directly.
 */
struct sp_header {
    uint8_t  proto_no;
    uint8_t  suite_id;
    uint16_t identifier;
    uint32_t seq;
} __attribute__((packed));

_Static_assert(sizeof(struct sp_header) == 8, "SPH wire format must be 8 bytes");

#ifdef __cplusplus
extern "C" {
#endif

enum sp_process_error {
    SP_ERROR_NONE = 0,
    SP_ERROR_INVALID_SPH,
    SP_ERROR_LENGTH_MISMATCH,
    SP_ERROR_SUITE_INVALID,
    SP_ERROR_KEY_LOOKUP_FAIL,
    SP_ERROR_SEQUENCE_STATE,
    SP_ERROR_CRYPTO,
};

/* Initialise the persistent sequence store before packet workers start. */
int sp_state_init(void);
enum sp_process_error sp_last_error(void);
bool sp_last_packet_was_protected(void);

bool is_sp_packet(const void *data, size_t len);
int packet_encrypt(void *data, size_t len, void *output);
int packet_decrypt(void *data, size_t len, void *output);

#ifdef __cplusplus
}
#endif

#endif /* SP_HEADER_H */
