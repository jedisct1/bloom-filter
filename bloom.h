
#ifndef __BLOOM_H__
#define __BLOOM_H__ 1

#include <sodium.h>
#include <stdlib.h>

typedef struct Bloom_ {
    unsigned char  skeys[2][crypto_shorthash_siphash24_KEYBYTES];
    unsigned char *bitmap;
    size_t         bitmap_size;
    size_t         k_num;
} Bloom;

Bloom * bloom_new(const size_t bitmap_size, const size_t items_count);

void bloom_free(Bloom * const bloom);

void bloom_set(const Bloom * const bloom, const char * const item,
               const size_t item_len);

_Bool bloom_check(const Bloom * const bloom, const char * const item,
                  const size_t item_len);

_Bool bloom_check_and_set(const Bloom * const bloom, const char * const item,
                          const size_t item_len);

#endif
