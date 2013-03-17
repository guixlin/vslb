#include "rsa.h"

void
rsa_free(rsa_context_t *ctx)
{
	if (ctx != NULL) {
		bn_free(&ctx->N);
		bn_free(&ctx->E);
		bn_free(&ctx->D);
		bn_free(&ctx->P);
		bn_free(&ctx->Q);
		bn_free(&ctx->DP);
		bn_free(&ctx->DQ);
		bn_free(&ctx->QP);
		bn_free(&ctx->RN);
		bn_free(&ctx->RP);
		bn_free(&ctx->RQ);
	}
}

int
rsa_gen_key(rsa_context_t *ctx, int nbits, int exponent,
            unsigned long (*rng_f)(void *), void *rng_d)
{
	int ret;
	bignum_t P1, Q1, H, G;

	if (nbits < 128 || exponent < 3) {
		return RSA_INVALID_PARAM;
	}

	bzero(&P1, sizeof(P1));
	bzero(&Q1, sizeof(Q1));
	bzero(&G, sizeof(G));
	bzero(&H, sizeof(H));
	/*
	 * find primes P and Q with Q < P, so that:
	 *      GCD(E, (P-1)*(Q-1)) = 1
	 */
	BN_CHK(bn_lset(&ctx->E, exponent));
	nbits >>= 1;
	do {
		BN_CHK(bn_gen_prime(&ctx->P, nbits, 0, rng_f, rng_d));
		BN_CHK(bn_gen_prime(&ctx->Q, nbits, 0, rng_f, rng_d));

		if (bn_cmp_bn(&ctx->P, &ctx->Q) == 0) {
			continue;
		}

		if (bn_cmp_bn(&ctx->P, &ctx->Q) < 0) {
			bn_swap(&ctx->P, &ctx->Q);
		}

		BN_CHK(bn_mul_bn(&ctx->N, &ctx->P, &ctx->Q));
		BN_CHK(bn_sub_int(&P1, &ctx->P, 1));
		BN_CHK(bn_sub_int(&Q1, &ctx->Q, 1));
		BN_CHK(bn_mul_bn(&H, &P1, &Q1));
		BN_CHK(bn_gcd(&G, &ctx->E, &H));
	} while (bn_cmp_int(&G, 1) != 0);

	/*
	 * D = E^-1 mod((P-1)*(Q-1))
	 * DP = D mod (P-1)
	 * DQ = D mod (Q-1)
	 * QP = Q^-1 mod P1
	 */
	BN_CHK(bn_inv_mod(&ctx->D, &ctx->E, &H));
	BN_CHK(bn_mod_bn(&ctx->DP, &ctx->D, &P1));
	BN_CHK(bn_mod_bn(&ctx->DQ, &ctx->D, &Q1));
	BN_CHK(bn_inv_mod(&ctx->QP, &ctx->Q, &ctx->P));

	ctx->len = (bn_msb(&ctx->N) + 7) >> 3;

cleanup:
	if (ret != RSA_SUCCESS) {
		rsa_free(ctx);

		return (RSA_KEY_GEN_FAILED | ret);
	}

	return RSA_SUCCESS;
}

