/*******************************************************************************
 * Copyright (c) 2013-2015, 2021 Pieter Wuille, Gregory Maxwell, Peter Dettman *
 * Distributed under the MIT software license, see the accompanying            *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.        *
 *******************************************************************************/

#ifndef SECP256K1_ECMULT_GEN_IMPL_H
#define SECP256K1_ECMULT_GEN_IMPL_H

#include "util.h"
#include "scalar.h"
#include "group.h"
#include "ecmult_gen.h"
#include "hash_impl.h"
#include "precomputed_ecmult_gen.h"

static void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context *ctx) {
    secp256k1_ecmult_gen_blind(ctx, NULL);
    ctx->built = 1;
}

static int secp256k1_ecmult_gen_context_is_built(const secp256k1_ecmult_gen_context* ctx) {
    return ctx->built;
}

static void secp256k1_ecmult_gen_context_clear(secp256k1_ecmult_gen_context *ctx) {
    ctx->built = 0;
    secp256k1_scalar_clear(&ctx->scalar_offset);
    secp256k1_ge_clear(&ctx->final_point_add);
}

/* Compute the scalar (2^COMB_BITS - 1) / 2. */
static void secp256k1_ecmult_gen_scalar_diff(secp256k1_scalar* diff) {
    int i;

    /* Compute scalar -1/2. */
    secp256k1_scalar neghalf = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 2);
    secp256k1_scalar_inverse_var(&neghalf, &neghalf);
    secp256k1_scalar_negate(&neghalf, &neghalf);

    /* Compute offset = 2^(COMB_BITS - 1). */
    secp256k1_scalar_set_int(diff, 1);
    for (i = 0; i < COMB_BITS - 1; ++i) {
        secp256k1_scalar_add(diff, diff, diff);
    }

    /* The result is the sum of 2^(COMB_BITS - 1) + (-1/2). */
    secp256k1_scalar_add(diff, diff, &neghalf);
}

static void secp256k1_ecmult_gen(const secp256k1_ecmult_gen_context *ctx, secp256k1_gej *r, const secp256k1_scalar *gn) {
    uint32_t comb_off;
    secp256k1_ge add;
    secp256k1_fe neg;
    secp256k1_ge_storage adds;
    secp256k1_scalar tmp;
    /* Array of uint32_t values large enough to store COMB_BITS bits. Only the bottom
     * 8 are ever nonzero, but having the zero padding at the end if COMB_BITS>256
     * avoids the need to deal with out-of-bounds reads from a scalar. */
    uint32_t recoded[(COMB_BITS + 31) >> 5] = {0};
    int first = 1, i;

    memset(&adds, 0, sizeof(adds));

    /* We want to compute R = gn*G.
     *
     * To blind the scalar used in the computation, we rewrite this to be R = (gn-b)*G + b*G, with
     * a value b determined by the context. b*G is precomputed as ctx->final_point_add, so we're
     * left with computing R = (gn-b)*G + ctx->final_point_add.
     *
     * The multiplication (gn-b)*G will be performed using a signed-digit multi-comb (see Section
     * 3.3 of "Fast and compact elliptic-curve cryptography" by Mike Hamburg
     * (https://eprint.iacr.org/2012/309).
     *
     * Let comb(s,P) = sum((2*s_i-1)*2^i*P for i=0..COMB_BITS-1), where s_i is the i'th bit of the
     * binary representation of scalar s. So the s_i values determine whether -2^i*P (s_i=0) or
     * +2^i*P (s_1) are added together. By manipulating:
     *
     *     comb(s,P) = sum((2*s_i-1)*2^i*P for i=0..COMB_BITS-1)
     * <=> comb(s,P) = sum((2*s_i-1)*2^i for i=0..COMB_BITS-1) * P
     * <=> comb(s,P) = (2*sum(s_i*2^i for i=0..COMB_BITS-1) - sum(2^i for i=0..COMB_BITS-1)) * P
     * <=> comb(s,P) = (2*s - (2^COMB_BITS - 1)) * P
     *
     * Thus (gn-b)*G can be written as c(s,G) if gn-b = 2*s - (2^COMB_BITS - 1), or
     * s = (gn - b + (2^COMB_BITS - 1))/2 mod order.
     *
     * We use an alternative that avoids the modular division by two: we write (gn-b)*G = c(d,G/2).
     * For that to hold it must be the case that (gn-b)*G = (2*d + 2^COMB_BITS - 1) * (G/2), or
     * d = (gn + (2^COMB_BITS - 1)/2 - b) mod order.
     *
     * 2^COMB_BITS - 1)/2 - b is precomputed as ctx->scalar_offset, so our final equations become:
     *
     *   d = gn + ctx->scalar_offset (mod order)
     *   R = comb(d, G/2) + ctx->final_point_add.
     *
     * The comb function is computed by summing + or - 2^(i-1)*G, for i=0..COMB_BITS-1, depending
     * on the value of the bits d_i of the binary representation of scalar d.
     */

    /* Compute the scalar (gn + ctx->scalar_offset). */
    secp256k1_scalar_add(&tmp, &ctx->scalar_offset, gn);
    /* Convert to recoded array. */
    for (i = 0; i < 8 && i < ((COMB_BITS + 31) >> 5); ++i) {
        recoded[i] = secp256k1_scalar_get_bits(&tmp, 32 * i, 32);
    }
    secp256k1_scalar_clear(&tmp);

    /* In secp256k1_ecmult_gen_prec_table we have precomputed sums of the
     * (2*d_i-1) * 2^(i-1) * G points, for various combinations of i positions.
     * We rewrite our equation in terms of these table entries.
     *
     * Let mask(b) = sum(2^(b*COMB_TEETH + t)*COMB_SPACING for t=0..COMB_TEETH-1),
     * with b ranging from 0 to COMB_BLOCKS-1. So for example with COMB_BLOCKS=11,
     * COMB_TEETH=6, COMB_SPACING=4, we would have:
     *   mask(0)  = 2^0   + 2^4   + 2^8   + 2^12  + 2^16  + 2^20,
     *   mask(1)  = 2^24  + 2^28  + 2^32  + 2^36  + 2^40  + 2^44,
     *   mask(2)  = 2^48  + 2^52  + 2^56  + 2^60  + 2^64  + 2^68,
     *   ...
     *   mask(10) = 2^240 + 2^244 + 2^248 + 2^252 + 2^256 + 2^260
     *
     * Imagine we have a table(b,m) function which can look up, given b and
     * m=(recoded & mask(b)), the sum of (2*d_i-1)*2^(i-1)*G for all bit positions
     * i set in mask(b). In our example, table(0, 1 + 2^8 + 2^20) would be equal to
     * (2^-1 - 2^3 + 2^7 - 2^11 - 2^15 + 2^19)*G.
     *
     * With that, we can rewrite R as:
     *   1*(table(0, recoded & mask(0)) + table(1, recoded & mask(1)) + ...)
     * + 2*(table(0, (recoded/2) & mask(0)) + table(1, (recoded/2) & mask(1)) + ...)
     * + 4*(table(0, (recoded/4) & mask(0)) + table(1, (recoded/4) & mask(1)) + ...)
     * + ...
     * + 2^(COMB_SPACING-1)*(table(0, (recoded/2^(COMB_SPACING-1)) & mask(0)) + ...)
     * + ctx->final_point_add.
     *
     * This is implemented using an outer loop that runs in reverse order over the lines
     * of this equation, which in each iteration runs an inner loop that adds the terms
     * of that line and the doubles the result before proceeding to the next line.
     * In pseudocode:
     *   R = infinity
     *   for comb_off in range(COMB_SPACING - 1, -1, -1):
     *     for block in range(COMB_BLOCKS):
     *       R += table(block, (recoded >> comb_off) & mask(block))
     *     if comb_off > 0:
     *       R = 2*R
     *   R += final_point_add
     *   return R
     *
     * The last question is how to implement the table(b,m) function. For any value of
     * b, m=(recoded & mask(b)) can only take on at most 2^COMB_TEETH possible values
     * (the last one may have fewer as there mask(b) may the curve order). So we could
     * create COMB_BLOCK tables which contain a value for each such m value.
     *
     * Due to the fact that every table entry is a sum of positive and negative powers
     * of two multiplied by G, every table will contains pairs of negated points:
     * if all the masked bits in m flip, the table value is negated. We can exploit this
     * to only store the first half of every table. If an entry from the second half is
     * needed, we look up its bit-flipped version instead, and conditionally negate it.
     *
     * secp256k1_ecmult_gen_prec_table[b][index] stores the table(b,m) entries. Index
     * is the relevant bits of m packed together without gaps. */

    /* Outer loop: iterate over comb_off from COMB_SPACING - 1 down to 0. */
    comb_off = COMB_SPACING - 1;
    while (1) {
        uint32_t block;
        uint32_t bit_pos = comb_off;
        /* Inner loop: for each block, add table entries to the result. */
        for (block = 0; block < COMB_BLOCKS; ++block) {
            /* Gather the mask(block)-selected bits of recoded into bits. They're packed
             * together: bit (tooth) of bits = bit
             * ((block*COMB_TEETH + tooth)*COMB_SPACING + comb_off) of recoded. */
            uint32_t bits = 0, sign, abs, index, tooth;
            for (tooth = 0; tooth < COMB_TEETH; ++tooth) {
                /* Instead of reading individual bits here to construct bits, build up
                 * the result by xoring shifted reads together. In every iteration, one
                 * additional bit is made correct, starting at the bottom. The bits
                 * above that contain junk. This reduces leakage from single bits. See
                 * https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-alam.pdf
                 */
                uint32_t bitdata = recoded[bit_pos >> 5] >> (bit_pos & 0x1f);
                bits &= ~(1 << tooth);
                bits ^= bitdata << tooth;
                bit_pos += COMB_SPACING;
            }

            /* If the top bit of bits is 1, conditionally flip them all (corresponding
             * to looking up the negated table value), and remember to negate the
             * result in sign. */
            sign = (bits >> (COMB_TEETH - 1)) & 1;
            abs = (bits ^ -sign) & (COMB_POINTS - 1);
            // VERIFY_CHECK(sign == 0 || sign == 1);
            // VERIFY_CHECK(abs < COMB_POINTS);

            /** This uses a conditional move to avoid any secret data in array indexes.
             *   _Any_ use of secret indexes has been demonstrated to result in timing
             *   sidechannels, even when the cache-line access patterns are uniform.
             *  See also:
             *   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
             *    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
             *   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
             *    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
             *    (https://www.tau.ac.il/~tromer/papers/cache.pdf)
             */
            for (index = 0; index < COMB_POINTS; ++index) {
                secp256k1_ge_storage_cmov(&adds, &secp256k1_ecmult_gen_prec_table[block][index], index == abs);
            }

            /* Set add=adds or add=-adds, in constant time, based on sign. */
            secp256k1_ge_from_storage(&add, &adds);
            secp256k1_fe_negate(&neg, &add.y, 1);
            secp256k1_fe_cmov(&add.y, &neg, sign);

            /* Add the looked up and conditionally negated value to r. */
            if (EXPECT(first, 0)) {
                /* If this is the first table lookup, we can skip addition. */
                secp256k1_gej_set_ge(r, &add);
                /* Give the entry a random Z coordinate to blind intermediary results. */
                secp256k1_gej_rescale(r, &ctx->proj_blind);
                first = 0;
            } else {
                secp256k1_gej_add_ge(r, r, &add);
            }
        }

        /* Double the result, except in the last iteration. */
        if (comb_off-- == 0) break;
        secp256k1_gej_double(r, r);
    }

    /* Correct for the scalar_offset added at the start (final_point_add = b*G, while b was
     * subtracted from the input scalar gn). */
    secp256k1_gej_add_ge(r, r, &ctx->final_point_add);

    /* Cleanup. */
    secp256k1_fe_clear(&neg);
    secp256k1_ge_clear(&add);
    memset(&adds, 0, sizeof(adds));
    memset(&recoded, 0, sizeof(recoded));
}

static void secp256k1_ecmult_gen2(const secp256k1_ecmult_gen_context *ctx, secp256k1_gej *r, const secp256k1_scalar *gn) {
    uint32_t comb_off;
    secp256k1_ge add;
    secp256k1_fe neg;
    secp256k1_ge_storage adds;
    secp256k1_scalar tmp;
    uint32_t recoded[(COMB_BITS + 31) >> 5] = {0};
    int first = 1, i;

    memset(&adds, 0, sizeof(adds));
    secp256k1_scalar_add(&tmp, &ctx->scalar_offset, gn);
    for (i = 0; i < 8 && i < ((COMB_BITS + 31) >> 5); ++i) {
        recoded[i] = secp256k1_scalar_get_bits(&tmp, 32 * i, 32);
    }
    secp256k1_scalar_clear(&tmp);
    comb_off = COMB_SPACING - 1;
    while (1) {
        uint32_t block;
        uint32_t bit_pos = comb_off;
        for (block = 0; block < COMB_BLOCKS; ++block) {
            uint32_t bits = 0, sign, abs, index, tooth;
            for (tooth = 0; tooth < COMB_TEETH; ++tooth) {
                uint32_t bitdata = recoded[bit_pos >> 5] >> (bit_pos & 0x1f);
                bits &= ~(1 << tooth);
                bits ^= bitdata << tooth;
                bit_pos += COMB_SPACING;
            }

            sign = (bits >> (COMB_TEETH - 1)) & 1;
            abs = (bits ^ -sign) & (COMB_POINTS - 1);

            for (index = 0; index < COMB_POINTS; ++index) {
                secp256k1_ge_storage_cmov(&adds, &secp256k1_ecmult_gen_prec_table[block][index], index == abs);
            }

            /* Set add=adds or add=-adds, in constant time, based on sign. */
            secp256k1_ge_from_storage(&add, &adds);
            secp256k1_fe_negate(&neg, &add.y, 1);
            secp256k1_fe_cmov(&add.y, &neg, sign);

            /* Add the looked up and conditionally negated value to r. */
            if (EXPECT(first, 0)) {
                /* If this is the first table lookup, we can skip addition. */
                secp256k1_gej_set_ge(r, &add);
                /* Give the entry a random Z coordinate to blind intermediary results. */
                first = 0;
            } else {
                secp256k1_gej_add_ge(r, r, &add);
            }
        }
        if (comb_off-- == 0) break;
        secp256k1_gej_double(r, r);
    }
    secp256k1_fe_clear(&neg);
    secp256k1_ge_clear(&add);
    memset(&adds, 0, sizeof(adds));
    memset(&recoded, 0, sizeof(recoded));
}

static void secp256k1_ecmult_gen1(const secp256k1_ecmult_gen_context *ctx, secp256k1_gej *r, const secp256k1_scalar *gn) {
    int g = 256;
    int n = 32;
    unsigned char k[32];
    int i;
    secp256k1_scalar_get_b32(k, gn);
    for (i = 0; i < n; i++) {
        secp256k1_gej_add_var(r, r, &ctx->table[i*g + k[i]], NULL);
    }
}

static void secp256k1_ecmult_gen3(const secp256k1_ecmult_gen_context *ctx, secp256k1_gej *r, const secp256k1_scalar *gn) {
    int g = 256;
    int n = 32;
    unsigned char k[32];
    int i;
    secp256k1_scalar_get_b32(k, gn);
    for (i = 0; i < n; i++) {
        secp256k1_gej_add_ge(r, r, &ctx->tables[i*g + k[32-i]]);
        // secp256k1_gej_add_var(r, r, &ctx->table[i*g + k[i]], NULL);
    }
}

/* Setup blinding values for secp256k1_ecmult_gen. */
static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32) {
    secp256k1_scalar b;
    secp256k1_scalar diff;
    secp256k1_gej gb;
    secp256k1_fe f;
    unsigned char nonce32[32];
    secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char keydata[64] = {0};

    /* Compute the (2^COMB_BITS - 1)/2 term once. */
    secp256k1_ecmult_gen_scalar_diff(&diff);

    if (seed32 == NULL) {
        /* When seed is NULL, reset the final point and blinding value. */
        secp256k1_ge_neg(&ctx->final_point_add, &secp256k1_ge_const_g);
        secp256k1_scalar_add(&ctx->scalar_offset, &secp256k1_scalar_one, &diff);
        ctx->proj_blind = secp256k1_fe_one;
    }
    /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
    secp256k1_scalar_get_b32(nonce32, &ctx->scalar_offset);
    /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
     *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
     *   asking the caller for blinding values directly and expecting them to retry on failure.
     */
    memcpy(keydata, nonce32, 32);
    if (seed32 != NULL) {
        memcpy(keydata + 32, seed32, 32);
    }
    secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, seed32 ? 64 : 32);
    memset(keydata, 0, sizeof(keydata));

    /* Compute projective blinding factor (cannot be 0). */
    secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
    secp256k1_fe_set_b32(&f, nonce32);
    secp256k1_fe_cmov(&f, &secp256k1_fe_one, secp256k1_fe_is_zero(&f));
    ctx->proj_blind = f;

    /* For a random blinding value b, set scalar_offset=diff-n, final_point_add=bG */
    secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
    secp256k1_scalar_set_b32(&b, nonce32, NULL);
    /* The blinding value cannot be zero, as that would mean final_point_add = infinity,
     * which secp256k1_gej_add_ge cannot handle. */
    secp256k1_scalar_cmov(&b, &secp256k1_scalar_one, secp256k1_scalar_is_zero(&b));
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);
    memset(nonce32, 0, 32);
    secp256k1_ecmult_gen(ctx, &gb, &b);
    secp256k1_scalar_negate(&b, &b);
    secp256k1_scalar_add(&ctx->scalar_offset, &b, &diff);
    secp256k1_ge_set_gej(&ctx->final_point_add, &gb);

    /* Clean up. */
    secp256k1_scalar_clear(&b);
    secp256k1_gej_clear(&gb);
}

#endif /* SECP256K1_ECMULT_GEN_IMPL_H */
