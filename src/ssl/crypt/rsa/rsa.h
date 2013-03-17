/*
 * RSA implement in kernel
 *
 */
#ifndef _KERN_RSA_H_
#define _KERN_RSA_H_

#include "bignum.h"

enum {
	RSA_SUCCESS = 0,
	RSA_FAILURE,
	RSA_INVALID_PARAM,
	RSA_KEY_GEN_FAILED
};

/*
 * PKCS#1 stuff
 */
#define RSA_RAW		0
#define RSA_MD2		2
#define RSA_MD4		3
#define RSA_MD5		4
#define RSA_SHA1	5

/*
 * DigestInfo ::= SEQUENCE {
 *        digestAlgorithm DigestAlgorithmIdentifier,
 *        digest Digest
 * }
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * Digest ::= OCTET STRING
 */
#define ASN1_HASH_MDX                           \
	"\x30\x20\x30\x0C\x06\x08\x2A\x86\x48"  \
        "\x86\xF7\x0D\x02\x00\x05\x00\x04\x10"

#define ASN1_HASH_SHA1                          \
	"\x30\x21\x30\x09\x06\x05\x2B\x0E\x03"  \
        "\x02\x1A\x05\x00\x04\x14"

#define RSA_F4		0x10001L
#define RSA_3		0x03L

typedef struct rsa_context {
	int ver;	/* should be 0 for current */
	int len;	/* sizeof(N) */
	bignum_t N;	/* public modulus */
	bignum_t E;	/* public exponent */
	bignum_t D;	/* private exponent */

	bignum_t P;	/* 1st prime factor */
	bignum_t Q;	/* 2nd prime factor */
	bignum_t DP;	/* D mod (P-1) */
	bignum_t DQ;	/* D mod (Q-1) */
	bignum_t QP;	/* inverse of Q % P */

	bignum_t RN;	/* cached R^2 mod N */
	bignum_t RP;	/* cached R^2 mod P */
	bignum_t RQ;	/* cached R^2 mod Q */
} rsa_context_t;

void rsa_free(rsa_context_t *ctx);

/*
 * Generate an RSA keypair
 */
int rsa_gen_key(rsa_context_t *ctx, int nbits, int exponent,
                unsigned long (*rng_f)(void *), void *rng_d);

#endif

