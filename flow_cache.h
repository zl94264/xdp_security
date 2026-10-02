#ifndef FLOW_CACHE_H
#define FLOW_CACHE_H

#include <stdbool.h>
#include <stdint.h>

#include "hkdf_fuc.h"

struct flow_state {
    struct flow_id fid;
    /* Stable policy-selected cache key; identifier may advance on rollover. */
    uint16_t cache_identifier;
    uint16_t identifier;
    uint8_t direction;
    uint8_t protocol;
    unsigned char flow_key[SM4_KEY_LENGTH];
    unsigned char iv_key[SM4_KEY_LENGTH];
    uint64_t next_seq;
    uint64_t seq_limit;
    uint64_t last_seen_ns;
    bool valid;
};

#define FLOW_CACHE_ERROR         -1
#define FLOW_CACHE_SEQ_EXHAUSTED -2

/* Load and exclusively lock the persistent transmit-sequence database. */
int flow_cache_global_init(void);
void flow_cache_global_cleanup(void);

/* Queue/thread-local cache lookup, with KDF only on a cache miss. */
int flow_cache_get(const struct five_tuple *tuple, uint16_t identifier,
                   bool transmit, struct flow_state **state_out);

/* Allocate a crash-safe unique sequence number from a reserved range. */
int flow_state_take_seq(struct flow_state *state, uint32_t *seq_out);

int flow_state_make_iv(const struct flow_state *state, uint32_t seq,
                       unsigned char iv_out[SM4_IV_LENGTH]);

/* Used for TCP FIN/RST; UDP entries are reclaimed by idle timeout. */
void flow_cache_expire(const struct five_tuple *tuple, uint16_t identifier);

#endif /* FLOW_CACHE_H */
