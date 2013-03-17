#ifndef _BIGNUM_H_
#define _BIGNUM_H_

#ifndef _KERNEL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/smp.h>
#include <sys/systm.h>
#endif

#define BN_CHK(func) if ((ret = func) != 0) goto cleanup

/* Define relative type */
typedef unsigned long t_int;
typedef unsigned int t_dbl __attribute__((mode(TI)));

enum {
	BN_SUCCESS = 0,
	BN_FAILURE,
	BN_INVALID_CHAR,
	BN_INVALID_RADIX,
	BN_BUFFER_TOO_SMALL,
	BN_INVALID_PARAM,
	BN_NOT_ACCEPTABLE,
	BN_NEGATIVE_VALUE,
	BN_DIVISION_BY_ZERO
};

#define ciL    (int) sizeof(t_int) /* chars in limb  */
#define biL    (ciL << 3)          /* bits  in limb  */
#define biH    (ciL << 2)          /* half limb size */

typedef struct bignum {
	int s;		/* sign */
	int n;		/* count of limbs */
	t_int *p;	/* pointer to the limbs */
} bignum_t;

#ifdef _KERNEL
#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_SSL_BN);
#endif

#define BN_MALLOC(p, len_) p = (t_int *)malloc(len_ * sizeof(t_int), M_SSL_BN, M_NOWAIT)
#define BN_FREE(p) free(p, M_SSL_BN)

#ifdef _USE_ZONE
/* Declare the zone for big number. */
int bn_zone_init(void);
#endif  /* _USE_ZONE */

#else
#define BN_MALLOC(p, len_) p = (t_int *)malloc(len_ * sizeof(t_int))
#define BN_FREE(p) free(p)
#endif   /* _KERNEL */

/*
 * Free the limbs' memory.
 */
void bn_free(bignum_t *p);

/* Enlarge X to the specified number of limbs */
int bn_grow(bignum_t *p, int number);

/* Copy the contents of y into x */
int bn_copy(bignum_t *x, bignum_t *y);
void bn_swap(bignum_t *x, bignum_t *y);

int bn_lset(bignum_t *x, int val);

int bn_read_string(bignum_t *x, int radix, char *s, int slen);
int bn_write_string(bignum_t *x, int radix, char *s, int *slen);

int bn_read_bin(bignum_t *x, unsigned char *bin, int blen);
int bn_write_bin(bignum_t *x, unsigned char *bin, int *blen);

int bn_msb(bignum_t *x);
int bn_lsb(bignum_t *x);

int bn_shift_L(bignum_t *x, int count);
int bn_shift_R(bignum_t *x, int count);

int bn_cmp_int(bignum_t *x, int z);
int bn_cmp_bn(bignum_t *x, bignum_t *y);
int bn_cmp_abs(bignum_t *x, bignum_t *y);

int bn_add_int(bignum_t *x, bignum_t *y, int z);
int bn_add_bn(bignum_t *x, bignum_t *y, bignum_t *z);
int bn_add_abs(bignum_t *x, bignum_t *y, bignum_t *z);

int bn_sub_int(bignum_t *x, bignum_t *y, int z);
int bn_sub_bn(bignum_t *x, bignum_t *y, bignum_t *z);
int bn_sub_abs(bignum_t *x, bignum_t *y, bignum_t *z);

int bn_mul_int(bignum_t *x, bignum_t *y, t_int z);
int bn_mul_bn(bignum_t *x, bignum_t *y, bignum_t *z);

int bn_div_int(bignum_t *q, bignum_t *r, bignum_t *y, int z);
int bn_div_bn(bignum_t *q, bignum_t *r, bignum_t *y, bignum_t *z);

int bn_mod_int(t_int *x, bignum_t *y, int z);
int bn_mod_bn(bignum_t *x, bignum_t *y, bignum_t *z);

int bn_exp_mod(bignum_t *x, bignum_t *y, bignum_t *e, bignum_t *n, bignum_t *rr);

int bn_gcd(bignum_t *x, bignum_t *y, bignum_t *z);

int bn_inv_mod(bignum_t *x, bignum_t *y, bignum_t *n);

int bn_is_prime(bignum_t *x);

int bn_gen_prime(bignum_t *x, int nbits, int dh_flag,
                 unsigned long (*rng_f)(void *), void *rng_d);

#ifdef _RUN_TEST
int bn_test(int verbose);
#endif

#endif   /* _BIGNUM_H_ */

