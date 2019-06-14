/* Author: Derrick Pallas, Argosy Labs
 * https://github.com/ArgosyLabs/hmac-blake2
 *
 * The contents of this file is free and unencumbered software released into the
 * public domain. For more information, please refer to <http://unlicense.org/>
*/
#ifndef HMAC_BLAKE2B_H
#define HMAC_BLAKE2B_H
#include <blake2.h>
#include <stdint.h>

typedef uint8_t hmac_blake2b_t[BLAKE2B_OUTBYTES];

typedef struct {
    uint64_t pad[BLAKE2B_BLOCKBYTES/sizeof(uint64_t)];
    blake2b_state state;
} hmac_blake2b_state;

void hmac_blake2b_init(hmac_blake2b_state *state, const uint8_t *key, size_t key_size);
void hmac_blake2b_update(hmac_blake2b_state *state, const uint8_t *message, size_t message_size);
void hmac_blake2b_final(hmac_blake2b_state *state, hmac_blake2b_t hmac);

void hmac_blake2b(hmac_blake2b_t hmac,
    const uint8_t *key, size_t key_size,
    const uint8_t *message, size_t message_size);

#endif//HMAC_BLAKE2B_H
