/*******************************************************************************
 * Copyright (c) 2013-2015, 2021 Pieter Wuille, Gregory Maxwell, Peter Dettman *
 * Distributed under the MIT software license, see the accompanying            *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.        *
 *******************************************************************************/

#ifndef SECP256K1_ECMULT_GEN_COMPUTE_TABLE_IMPL_H
#define SECP256K1_ECMULT_GEN_COMPUTE_TABLE_IMPL_H

#include "ecmult_gen_compute_table.h"
#include "group_impl.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "ecmult_gen.h"
#include "util.h"

static void secp256k1_ecmult_gen_compute_table(secp256k1_ge_storage* table, const secp256k1_ge* gen, int blocks, int teeth, int spacing) {
    size_t points = ((size_t)1) << (teeth - 1);
    size_t points_total = points * blocks;
    secp256k1_ge* prec = checked_malloc(&default_error_callback, points_total * sizeof(*prec));
    secp256k1_gej* ds = checked_malloc(&default_error_callback, teeth * sizeof(*ds));
    secp256k1_gej* vs = checked_malloc(&default_error_callback, points_total * sizeof(*vs));
    secp256k1_gej u;
    size_t vs_pos = 0;
    secp256k1_scalar half = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 2);
    int block, i;

    /* u is the running power of two times gen we're working with, initially gen/2. */
    secp256k1_scalar_inverse_var(&half, &half);
    secp256k1_gej_set_infinity(&u);
    for (i = 255; i >= 0; --i) {
        /* Use a very simple multiplication ladder to avoid dependency on ecmult. */
        secp256k1_gej_double_var(&u, &u, NULL);
        if (secp256k1_scalar_get_bits(&half, i, 1)) {
            secp256k1_gej_add_ge_var(&u, &u, gen, NULL);
        }
    }

    for (block = 0; block < blocks; ++block) {
        int tooth;
        /* Here u = 2^(block*teeth*spacing) * gen/2. */
        secp256k1_gej sum;
        secp256k1_gej_set_infinity(&sum);
        for (tooth = 0; tooth < teeth; ++tooth) {
            /* Here u = 2^((block*teeth + tooth)*spacing) * gen/2. */
            /* Make sum = sum(2^((block*teeth + t)*spacing), t=0..tooth). */
            secp256k1_gej_add_var(&sum, &sum, &u, NULL);
            /* Make u = 2^((block*teeth + tooth)*spacing + 1) * gen/2. */
            secp256k1_gej_double_var(&u, &u, NULL);
            /* Make ds[tooth] = u = 2^((block*teeth + tooth)*spacing + 1) * gen/2. */
            ds[tooth] = u;
            /* Make u = 2^((block*teeth + tooth + 1)*spacing), unless at the end. */
            if (block + tooth != blocks + teeth - 2) {
                int bit_off;
                for (bit_off = 1; bit_off < spacing; ++bit_off) {
                    secp256k1_gej_double_var(&u, &u, NULL);
                }
            }
        }
        /* Now u = 2^(block*(teeth + 1)*spacing) * gen/2. */

        /* Next, compute the table entries for block block in Jacobian coordinates.
         * The entries will occupy vs[block*points + i] for i=0..points-1.
         * We start by computing the first (i=0) value corresponding to all summed
         * powers of two times G being negative. */
        secp256k1_gej_neg(&vs[vs_pos++], &sum);
        /* And then teeth-1 times "double" the range of i values for which the table
         * is computed: in each iteration, double the table by taking an existing
         * table entry and adding ds[tooth]. */
        for (tooth = 0; tooth < teeth - 1; ++tooth) {
            size_t stride = ((size_t)1) << tooth;
            size_t index;
            for (index = 0; index < stride; ++index, ++vs_pos) {
                secp256k1_gej_add_var(&vs[vs_pos], &vs[vs_pos - stride], &ds[tooth], NULL);
            }
        }
    }
    VERIFY_CHECK(vs_pos == points_total);

    /* Convert all points simultaneously from secp256k1_gej to secp256k1_ge. */
    secp256k1_ge_set_all_gej_var(prec, vs, points_total);
    /* Convert all points from secp256k1_ge to secp256k1_ge_storage output. */
    for (block = 0; block < blocks; ++block) {
        size_t index;
        for (index = 0; index < points; ++index) {
            CHECK(!secp256k1_ge_is_infinity(&prec[block * points + index]));
            secp256k1_ge_to_storage(&table[block * points + index], &prec[block * points + index]);
        }
    }

    /* Free memory. */
    free(vs);
    free(ds);
    free(prec);
}

#endif /* SECP256K1_ECMULT_GEN_COMPUTE_TABLE_IMPL_H */
