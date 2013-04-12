
#include <assert.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sodium/crypto_shorthash_siphash24.h>
#include <sodium/randombytes.h>

#include "bloom.h"

static size_t
bloom_optimal_k_num(const Bloom * const bloom, const size_t bitmap_size,
                    const size_t items_count)
{
    const double m = (double) ((uint64_t) bitmap_size *
                               (uint64_t) sizeof *bloom->bitmap * CHAR_BIT);
    const double n = (double) items_count;
    size_t       k_num = (size_t) (double) ceil(m / n * log(2.0));

    if (k_num < (size_t) 1U) {
        k_num = (size_t) 1U;
    }
    return k_num;
}

static void
bloom_hash(const Bloom * const bloom, uint64_t * const hashes,
           const char * const item, const size_t item_len, const size_t k_i)
{
    assert(k_i < bloom->k_num);
    if (k_i < 2U) {
        crypto_shorthash_siphash24((unsigned char *) &hashes[k_i],
                                   (const unsigned char *) item,
                                   item_len, bloom->skeys[k_i]);
    } else {
        hashes[k_i] = hashes[0] +
            (((uint64_t) k_i * hashes[1]) % 0xffffffffffffffc5);
    }
}

static int
bloom_init(Bloom * const bloom, const size_t bitmap_size,
           const size_t items_count)
{
    if (bitmap_size >= UINT64_MAX / (sizeof *bloom->bitmap * CHAR_BIT)) {
        return -1;
    }
    bloom->k_num = bloom_optimal_k_num(bloom, bitmap_size, items_count);
    bloom->bitmap_bits = (uint64_t) bitmap_size *
        (uint64_t) sizeof *bloom->bitmap * CHAR_BIT;
    bloom->bitmap = calloc(sizeof *bloom->bitmap, bitmap_size);
    if (bloom->bitmap == NULL) {
        return -1;
    }
    randombytes_buf(&bloom->skeys[0], sizeof bloom->skeys[0]);
    randombytes_buf(&bloom->skeys[1], sizeof bloom->skeys[1]);

    return 0;
}

Bloom *
bloom_new(const size_t bitmap_size, const size_t items_count)
{
    Bloom *bloom;

    if ((bloom = malloc(sizeof *bloom)) == NULL) {
        return NULL;
    }
    if (bloom_init(bloom, bitmap_size, items_count) != 0) {
        free(bloom);
        return NULL;
    }
    return bloom;
}

void
bloom_free(Bloom * const bloom)
{
    free(bloom->bitmap);
    bloom->bitmap = NULL;
    free(bloom);
}

size_t
bloom_compute_bitmap_size(const size_t items_count, const double fp_p)
{
    double log2_2;
    
    log2_2 = log(2);
    log2_2 *= log2_2;
    return (size_t) llround((double) items_count * log(fp_p) /
                            (-8.0 * log2_2));
}

void
bloom_set(const Bloom * const bloom, const char * const item,
          const size_t item_len)
{
    uint64_t      hashes[bloom->k_num];
    uint64_t      bit_offset;
    size_t        k_i = (size_t) 0U;
    size_t        offset;
    unsigned char bit;

    do {
        bloom_hash(bloom, hashes, item, item_len, k_i);
        bit_offset = hashes[k_i] % bloom->bitmap_bits;
        offset = (size_t) (bit_offset / (sizeof *bloom->bitmap * CHAR_BIT));
        bit = (unsigned char) (bit_offset % (sizeof *bloom->bitmap * CHAR_BIT));
        bloom->bitmap[offset] |= (1U << bit);
    } while (++k_i < bloom->k_num);
}

_Bool
bloom_check(const Bloom * const bloom, const char * const item,
            const size_t item_len)
{
    uint64_t      hashes[bloom->k_num];
    uint64_t      bit_offset;
    size_t        k_i = (size_t) 0U;
    size_t        offset;
    unsigned char bit;

    do {
        bloom_hash(bloom, hashes, item, item_len, k_i);
        bit_offset = hashes[k_i] % bloom->bitmap_bits;
        offset = (size_t) (bit_offset / (sizeof *bloom->bitmap * CHAR_BIT));
        bit = (unsigned char) (bit_offset % (sizeof *bloom->bitmap * CHAR_BIT));
        if ((bloom->bitmap[offset] & (1U << bit)) == 0U) {
            return 0;
        }
    } while (++k_i < bloom->k_num);

    return 1;
}

_Bool
bloom_check_and_set(const Bloom * const bloom, const char * const item,
                    const size_t item_len)
{
    uint64_t      hashes[bloom->k_num];
    uint64_t      bit_offset;
    size_t        k_i = (size_t) 0U;
    size_t        offset;
    unsigned char bit;
    unsigned char bit_shifted;
    _Bool         found = 1;

    do {
        bloom_hash(bloom, hashes, item, item_len, k_i);
        bit_offset = hashes[k_i] % bloom->bitmap_bits;
        offset = (size_t) (bit_offset / (sizeof *bloom->bitmap * CHAR_BIT));
        bit = (unsigned char) (bit_offset % (sizeof *bloom->bitmap * CHAR_BIT));
        bit_shifted = (unsigned char) (1U << bit);
        found &= ((bloom->bitmap[offset] & bit_shifted) >> bit);
        bloom->bitmap[offset] |= bit_shifted;
    } while (++k_i < bloom->k_num);

    return found;
}
