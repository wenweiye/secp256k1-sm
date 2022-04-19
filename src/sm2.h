/***********************************************************************
 *                               yewenwei                              *
 ***********************************************************************/

#ifndef SECP256K1_SM2_H
#define SECP256K1_SM2_H

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int secp256k1_sm2_precomputed(const unsigned char *seckey, unsigned char *seckeyInv, unsigned char *seckeyInvSeckey);

static int secp256k1_ecdsa_sig_parse(secp256k1_scalar *r, secp256k1_scalar *s, const unsigned char *sig, size_t size);
static int secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const secp256k1_scalar *r, const secp256k1_scalar *s);
static int secp256k1_sm2_sig_verify(const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message);
static int secp256k1_sm2_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar* r, secp256k1_scalar* s, const secp256k1_scalar *message, const secp256k1_scalar *nonce);

#endif /* SECP256K1_SM2_H */