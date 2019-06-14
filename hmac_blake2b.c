/* Author: Derrick Pallas, Argosy Labs
 * https://github.com/ArgosyLabs/hmac-blake2
 *
 * The contents of this file is free and unencumbered software released into the
 * public domain. For more information, please refer to <http://unlicense.org/>
*/
#include "hmac_blake2b.h"
#include <string.h>

void
hmac_blake2b_init(hmac_blake2b_state *state, const uint8_t *key, size_t key_size) {
    if (key_size <= sizeof(state->pad)) {
        memcpy((uint8_t*)state->pad, key, key_size);
        memset((uint8_t*)state->pad + key_size, 0, sizeof(state->pad) - key_size);
    } else {
        blake2b_init(&state->state, BLAKE2B_OUTBYTES);
        blake2b_update(&state->state, key, key_size);
        blake2b_final(&state->state, (uint8_t*)state->pad, BLAKE2B_OUTBYTES);
        memset((uint8_t*)state->pad + BLAKE2B_OUTBYTES, 0, sizeof(state->pad) - BLAKE2B_OUTBYTES);
    }

    for (size_t i = 0; i < sizeof(state->pad)/sizeof(*state->pad); ++i)
        state->pad[i] ^= 0x3636363636363636ULL;

    blake2b_init(&state->state, BLAKE2B_OUTBYTES);
    blake2b_update(&state->state, (uint8_t*)state->pad, sizeof(state->pad));
}

void
hmac_blake2b_update(hmac_blake2b_state *state, const uint8_t *message, size_t message_size) {
    blake2b_update(&state->state, message, message_size);
}

void
hmac_blake2b_final(hmac_blake2b_state *state, hmac_blake2b_t hmac) {
    blake2b_final(&state->state, hmac, BLAKE2B_OUTBYTES);

    for (size_t i = 0; i < sizeof(state->pad)/sizeof(*state->pad); ++i)
        state->pad[i] ^= 0x3636363636363636ULL ^ 0x5c5c5c5c5c5c5c5cULL;

    blake2b_init(&state->state, BLAKE2B_OUTBYTES);
    blake2b_update(&state->state, (uint8_t*)state->pad, sizeof(state->pad));
    blake2b_update(&state->state, hmac, BLAKE2B_OUTBYTES);
    blake2b_final(&state->state, hmac, BLAKE2B_OUTBYTES);
}

void
hmac_blake2b(hmac_blake2b_t hmac,
        const uint8_t *key, size_t key_size,
        const uint8_t *message, size_t message_size
) {
    hmac_blake2b_state state;
    hmac_blake2b_init(&state, key, key_size);
    hmac_blake2b_update(&state, message, message_size);
    hmac_blake2b_final(&state, hmac);
}

//
