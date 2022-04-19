#ifndef SECP256K1_SM2_IMPL_H
#define SECP256K1_SM2_IMPL_H

#include "eckey.h"

#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult_gen.h"

static int secp256k1_sm2_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_scalar *seckeyInv, const secp256k1_scalar *seckeyInvSeckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce) {
    unsigned char b[32];
    secp256k1_gej rp;
    secp256k1_ge r;
    secp256k1_scalar tmp;

    secp256k1_ecmult_gen(ctx, &rp, nonce);
    secp256k1_ge_set_gej(&r, &rp);
    secp256k1_fe_normalize(&r.x);
    secp256k1_fe_get_b32(b, &r.x);
    secp256k1_scalar_set_b32(sigr, b, NULL);

    secp256k1_scalar_add(sigr, sigr, message);
    secp256k1_scalar_add(&tmp, sigr, nonce);

    if (secp256k1_scalar_is_zero(&tmp) || secp256k1_scalar_is_zero(sigr))
        return 0;

    secp256k1_scalar_mul(&tmp, sigr, seckeyInvSeckey);
    secp256k1_scalar_negate(&tmp, &tmp);
    secp256k1_scalar_mul(sigs, nonce, seckeyInv);
    secp256k1_scalar_add(sigs, sigs, &tmp);

    secp256k1_scalar_clear(&tmp);
    secp256k1_ge_clear(&r);
    secp256k1_gej_clear(&rp);

    return (int)(!secp256k1_scalar_is_zero(sigs));
}

static int secp256k1_sm2_sig_verify(const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message) {
    unsigned char c[32];
    secp256k1_scalar t, computed_r;
    secp256k1_gej pubkeyj, pr;
    secp256k1_ge pr_ge;

    if (secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(sigs)){
        printf("sigr || sigs is zero!\n");
        return 0;
    }

    secp256k1_scalar_add(&t, sigr, sigs);
    secp256k1_gej_set_ge(&pubkeyj, pubkey);
    secp256k1_ecmult(&pr, &pubkeyj, &t, sigs);
    if (secp256k1_gej_is_infinity(&pr))
    {
        printf("pr is infinity!\n");
        return 0;
    }

    secp256k1_ge_set_gej(&pr_ge, &pr);
    secp256k1_fe_normalize(&pr_ge.x);
    secp256k1_fe_get_b32(c, &pr_ge.x);
    secp256k1_scalar_set_b32(&computed_r, c, NULL);
    secp256k1_scalar_add(&computed_r, &computed_r, message);
    return secp256k1_scalar_eq(sigr, &computed_r);
}

#endif /* SECP256K1_SM2_IMPL_H */