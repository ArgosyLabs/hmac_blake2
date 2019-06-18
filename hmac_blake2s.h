/* Author: Derrick Pallas, Argosy Labs
 * https://github.com/ArgosyLabs/hmac-blake2
 *
 * The contents of this file is free and unencumbered software released into the
 * public domain. For more information, please refer to <http://unlicense.org/>
*/
#ifndef HMAC_BLAKE2S_H
#define HMAC_BLAKE2S_H

#include <blake2.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t hmac_blake2s_t[BLAKE2S_OUTBYTES];

typedef struct {
    uint64_t pad[BLAKE2S_BLOCKBYTES/sizeof(uint64_t)];
    blake2s_state state;
} hmac_blake2s_state;

void hmac_blake2s_init(hmac_blake2s_state *state, const uint8_t *key, size_t key_size);
void hmac_blake2s_update(hmac_blake2s_state *state, const uint8_t *message, size_t message_size);
void hmac_blake2s_final(hmac_blake2s_state *state, hmac_blake2s_t hmac);

void hmac_blake2s(hmac_blake2s_t hmac,
    const uint8_t *key, size_t key_size,
    const uint8_t *message, size_t message_size);

#ifdef __cplusplus
}
#endif

#endif//HMAC_BLAKE2S_H
