/*
 * bignum computing in kernel for AMD 64 CPU.
 * Referred on project wpa-supplant in Linux.
 *
 */
#include "kern_bignum.h"
#include "kern_bn_asm.h"

#ifdef _KERNEL
#ifdef MALLOC_DEFINE
MALLOC_DEFINE(M_SSL_BN, "ssl_bn", "ssl bignum");
#endif

typedef int (*rand_func_t)(void);
#endif

/* Convert between bits/chars and number of limbs */
#define BITS_TO_LIMBS(i)  (((i) + biL - 1)/biL)
#define CHARS_TO_LIMBS(i) (((i) + ciL - 1)/ciL)


/*
 * Free the limbs memory.
 */
void
bn_free(bignum_t *x)
{
	if (x->p != NULL) {
		BN_FREE(x->p);
		x->p = NULL;
	}

	x->n = 0;
	x->s = 0;
}

int
bn_grow(bignum_t *x, int nblimbs)
{
	int n = x->n;
#ifdef _KERNEL
	t_int *new = NULL;
#endif

	if (n < nblimbs) {
		if (x->s == 0) {
			x->s = 1;
		}
		x->n = nblimbs;

#ifdef _KERNEL
		BN_MALLOC(new, x->n);
		if (new == NULL) {
			sslstats.ssls_nomem++;
			return BN_FAILURE;
		}

		bcopy(x->p, new, n*ciL);
		BN_FREE(x->p);
		x->p = new;
#else
		x->p = (t_int *)realloc(x->p, x->n * ciL);
#endif
		if (x->p == NULL) {
			return BN_FAILURE;
		}

		bzero(x->p+n, (x->n-n)*ciL);
	}

	return BN_SUCCESS;
}

int
bn_copy(bignum_t *x, bignum_t *y)
{
	int i;

	if (x == y) {
		return BN_SUCCESS;
	}

	/* Look for the first non-zero byte */
	for (i = y->n - 1; i > 0; i--) {
		if (y->p[i] != 0) {
			break;
		}
	}
	i++;

	x->s = y->s;
	if (bn_grow(x, i) != BN_SUCCESS) {
		return BN_FAILURE;
	}

	bzero(x->p, x->n*ciL);
	bcopy(y->p, x->p, i*ciL);

	return BN_SUCCESS;
}

void
bn_swap(bignum_t *x, bignum_t *y)
{
	bignum_t z;

	bcopy(x, &z, sizeof(bignum_t));
	bcopy(y, x, sizeof(bignum_t));
	bcopy(&z, y, sizeof(bignum_t));
}

int
bn_lset(bignum_t *x, int z)
{
	if (bn_grow(x, 1) != BN_SUCCESS) {
		return BN_FAILURE;
	}

	bzero(x->p, x->n * ciL);
	x->p[0] = (z<0)?-z:z;
	x->s = (z < 0)?-1:1;

	return BN_SUCCESS;
}

static int
bn_a2i(t_int *d, int radix, char c)
{
	c += (0x20 *((c >= 'A') && (c <= 'Z')));

	if (c >= '0' && c <= '9') {
		*d = c - '0';
	} else if (c >= 'a' && c <= 'f') {
		*d = c - 'a' + 10;
	} else {
		return BN_INVALID_CHAR;
	}

	return BN_SUCCESS;
}

int
bn_read_string(bignum_t *x, int radix, char *s, int slen)
{
	int ret, i, j, n;
	t_int d;
	bignum_t z;

	if (radix < 2 || radix > 16) {
		return BN_INVALID_PARAM;
	}

	bzero(&z, sizeof(z));
	if (radix == 16) {
		n = BITS_TO_LIMBS(slen << 2);

		BN_CHK(bn_grow(x, n));
		BN_CHK(bn_lset(x, 0));

		for (i = slen - 1, j = 0; i >=0; i--, j++) {
			if (i == 0 && s[i] == '-') {
				x->s = -1;
				break;
			}

			BN_CHK(bn_a2i(&d, radix, s[i]));
			x->p[j/(ciL*2)] |= d << ((j%(ciL*2))<<2);
		}
	} else {
		BN_CHK(bn_lset(x, 0));

		for (i = 0; i < slen; i++) {
			if (i == 0 && s[i] == '-') {
				x->s = -1;
				break;
			}

			BN_CHK(bn_a2i(&d, radix, s[i]));
			BN_CHK(bn_mul_int(&z, x, radix));
			BN_CHK(bn_add_int(x, &z, d));
		}
	}

cleanup:
	bn_free(&z);
	return ret;
}

static int
bn_write_helper(bignum_t *x, int radix, char **p)
{
	int ret;
	t_int r;

	BN_CHK(bn_mod_int(&r, x, radix));
	BN_CHK(bn_div_int(x, NULL, x, radix));

	if (bn_cmp_int(x, 0) != 0) {
		BN_CHK(bn_write_helper(x, radix, p));
	}

	*(*p)++ = (r < 10)?((char)r+'0'):((char)r+'a');

cleanup:
	return ret;
}

int
bn_write_string(bignum_t *x, int radix, char *s, int *slen)
{
	int ret = BN_SUCCESS, n;
	char *p;
	bignum_t z;

	if (radix < 2 || radix > 16) {
		return BN_INVALID_RADIX;
	}

	n = bn_msb(x);
	if (radix >= 4) n >>= 1;
	if (radix == 16) n >>= 1;
	n += 3;

	if (*slen < n) {
		*slen = n;
		return BN_BUFFER_TOO_SMALL;
	}

	p = s;
	bzero(&z, sizeof(z));
	if (x->s == -1) {
		*p++ = '-';
	}

	if (radix == 16) {
		int i, c, j, k;

		for (i = x->n - 1, k = 0; i >= 0; i--) {
			for (j = ciL - 1; j >= 0; j--) {
				c = (x->p[i]>>(j<<3)) & 0xFF;

				if (c == 0 && k == 0 && (i + j) != 0) {
					continue;
				}

				p += snprintf(p, (*slen - (p - s)), "%02X", c);
				k = 1;
			}
		}
	} else {
		BN_CHK(bn_copy(&z, x));
		BN_CHK(bn_write_helper(&z, radix, &p));
	}

	*p++ = '\0';
	*slen = p - s;

cleanup:
	bn_free(&z);
	return ret;
}

int
bn_read_bin(bignum_t *x, unsigned char *bin, int blen)
{
	int ret, i, j, n;

	for (n = 0; n < blen; n++) {
		if (bin[n] != 0) {
			break;
		}
	}

	BN_CHK(bn_grow(x, CHARS_TO_LIMBS(blen - n)));
	BN_CHK(bn_lset(x, 0));

	for (i = blen-1, j = 0; i >= n; i--, j++) {
		x->p[j/ciL] |= (t_int)(bin[i] << ((j%ciL)<<3));
	}

cleanup:
	return ret;
}

int
bn_write_bin(bignum_t *x, unsigned char *bin, int *blen)
{
	int i, j, n;

	n = (bn_msb(x) + 7) >> 3;
	if (*blen < n) {
		*blen = n;
		return BN_BUFFER_TOO_SMALL;
	}

	bzero(bin, *blen);
	for (i = *blen - 1, j = 0; n > 0; i--, j++, n--) {
		bin[i] = (unsigned char)(x->p[j/ciL]>>((j%ciL)<<3));
	}

	return BN_SUCCESS;
}

int
bn_msb(bignum_t *x)
{
	int i, j;

	for (i = x->n - 1; i > 0; i--) {
		if (x->p[i] != 0) {
			break;
		}
	}

	for (j = biL - 1; j >= 0; j--) {
		if (((x->p[i] >> j) & 1) != 0) {
			break;
		}
	}

	return ((i*biL)+j+1);
}

int
bn_lsb(bignum_t *x)
{
	int i, j, count = 0;

	for (i = 0; i < x->n; i++) {
		for (j = 0; j < (int)biL; j++, count++) {
			if (((x->p[i] >> j) & 1) != 0) {
				return count;
			}
		}
	}

	return 0;
}

int
bn_shift_L(bignum_t *x, int count)
{
	int ret, i, v0, t1;
	t_int r0 = 0, r1;

	v0 = count / biL;
	t1 = count & (biL - 1);

	i = bn_msb(x) + count;
	if (x->n * (int)biL < i) {
		BN_CHK(bn_grow(x, BITS_TO_LIMBS(i)));
	}

	ret = 0;
	if (v0 > 0) {
		for (i = x->n - 1; i >= v0; i--) {
			x->p[i] = x->p[i-v0];
		}

		for (; i >= 0; i--) {
			x->p[i] = 0;
		}
	}

	if (t1 > 0) {
		for (i = v0; i < x->n; i++) {
			r1 = x->p[i] >> (biL - t1);
			x->p[i] <<= t1;
			x->p[i] |= r0;
			r0 = r1;
		}
	}

cleanup:
	return ret;
}

int
bn_shift_R(bignum_t *x, int count)
{
	int i, v0, v1;
	t_int r0 = 0, r1;

	v0 = count / biL;
	v1 = count & (biL - 1);
	if (v0 > 0) {
		for (i = 0; i < x->n - v0; i++) {
			x->p[i] = x->p[i+v0];
		}

		for (; i < x->n; i++) {
			x->p[i] = 0;
		}
	}

	if (v1 > 0) {
		for (i = x->n-1; i >= 0; i--) {
			r1 = x->p[i] << (biL - v1);
			x->p[i] >>= v1;
			x->p[i] |= r0;
			r0 = r1;
		}
	}

	return BN_SUCCESS;
}

int
bn_cmp_abs(bignum_t *x, bignum_t *y)
{
	int i, j;

	for (i = x->n - 1; i >= 0; i--) {
		if (x->p[i] != 0) {
			break;
		}
	}

	for (j = y->n - 1; j >= 0; j--) {
		if (y->p[j] != 0) {
			break;
		}
	}

	if (i < 0 && j < 0) {
		return 0;
	}

	if (i > j) {
		return 1;
	}

	if (i < j) {
		return -1;
	}

	for (; i >= 0; i--) {
		if (x->p[i] > y->p[i]) {
			return 1;
		}

		if (x->p[i] < y->p[i]) {
			return -1;
		}
	}

	return 0;
}

int
bn_cmp_bn(bignum_t *x, bignum_t *y)
{
	int i, j;

	for (i = x->n - 1; i >= 0; i--) {
		if (x->p[i] != 0) {
			break;
		}
	}

	for (j = y->n - 1; j >= 0; j--) {
		if (y->p[j] != 0) {
			break;
		}
	}

	if (i < 0 && j < 0) {
		return 0;
	}

	if (i > j) {
		return x->s;
	}

	if (i < j) {
		return -(x->s);
	}

	if (x->s > 0 && y->s < 0) {
		return 1;
	}

	if (x->s < 0 && y->s > 0) {
		return -1;
	}

	for (; i >= 0; i--) {
		if (x->p[i] > y->p[i]) {
			return x->s;
		}

		if (x->p[i] < y->p[i]) {
			return -(x->s);
		}
	}

	return 0;
}

int
bn_cmp_int(bignum_t *x, int z)
{
	bignum_t y;
	t_int p[1];

	*p = (z < 0) ? -z : z;
	y.s = (z < 0)?-1:1;
	y.n = 1;
	y.p = p;

	return bn_cmp_bn(x, &y);
}

int
bn_add_abs(bignum_t *x, bignum_t *y, bignum_t *z)
{
	int ret, i, j;
	t_int *o, *p, c;

	if (x == z) {
		bignum_t *k = y;
		y = x;
		z = k;
	}

	if (x != y) {
		BN_CHK(bn_copy(x, y));
	}

	for (j = z->n-1; j >= 0; j--) {
		if (z->p[j] != 0) {
			break;
		}
	}

	BN_CHK(bn_grow(x, j+1));
	o = z->p;
	p = x->p;
	c = 0;
	for (i = 0; i <= j; i++, o++, p++) {
		*p += c;
		c = (*p < c);

		*p += *o;
		c += (*p < *o);
	}

	while (c != 0) {
		if (i >= x->n) {
			BN_CHK(bn_grow(x, i+1));
			p = x->p + i;
		}

		*p += c;
		c = (*p < c);
		i++;
	}

cleanup:
	return ret;
}

int
bn_add_bn(bignum_t *x, bignum_t *y, bignum_t *z)
{
	int ret, s = y->s;

	if (y->s * z->s < 0) {
		if (bn_cmp_abs(y, z) >= 0) {
			BN_CHK(bn_sub_abs(x, y, z));
			x->s = s;
		} else {
			BN_CHK(bn_sub_abs(x, z, y));
			x->s = -s;
		}
	} else {
		BN_CHK(bn_add_abs(x, y, z));
		x->s = s;
	}

cleanup:
	return ret;
}

int
bn_add_int(bignum_t *x, bignum_t *y, int z)
{
	bignum_t k;
	t_int p[1];

	p[0] = (z < 0)? -z:z;
	k.s = (z < 0)? -1:1;
	k.n = 1;
	k.p = p;

	return bn_add_bn(x, y, &k);
}

static void
bn_sub_helper(int n, t_int *s, t_int *d)
{
	int i;
	t_int c, z;

	for (i = c = 0; i < n; i++, s++, d++) {
		z = (*d < c);
		*d -= c;
		c = (*d < *s) + z;
		*d -= *s;
	}

	while (c != 0) {
		z = (*d < c);
		*d -= c;
		c = z;
		i++;
		d++;
	}
}

int
bn_sub_abs(bignum_t *x, bignum_t *y, bignum_t *z)
{
	bignum_t k;
	int ret, i;

	if (bn_cmp_abs(y, z) < 0) {
		return BN_NEGATIVE_VALUE;
	}

	bzero(&k, sizeof(k));
	if (x == z) {
		BN_CHK(bn_copy(&k, z));
		z = &k;
	}

	if (x != y) {
		BN_CHK(bn_copy(x, y));
	}

	ret = BN_SUCCESS;
	for (i = z->n-1; i >= 0; i--) {
		if (z->p[i] != 0) {
			break;
		}
	}

	bn_sub_helper(i+1, z->p, x->p);

cleanup:
	bn_free(&k);
	return ret;
}

int
bn_sub_bn(bignum_t *x, bignum_t *y, bignum_t *z)
{
	int ret, s = y->s;

	if (y->s * z->s > 0) {
		if (bn_cmp_abs(y, z) >= 0) {
			BN_CHK(bn_sub_abs(x, y, z));
			x->s = s;
		} else {
			BN_CHK(bn_sub_abs(x, z, y));
			x->s = -s;
		}
	} else {
		BN_CHK(bn_add_abs(x, y, z));
		x->s = s;
	}

cleanup:
	return ret;
}

int
bn_sub_int(bignum_t *x, bignum_t *y, int z)
{
	bignum_t k;
	t_int p[1];

	p[0] = (z < 0)? -z:z;
	k.s = (z < 0)? -1:1;
	k.n = 1;
	k.p = p;

	return bn_sub_bn(x, y, &k);
}

static void
bn_mul_helper(int i, t_int *s, t_int *d, t_int b)
{
	t_int c = 0, t = 0;

#ifdef MULADDC_HUIT
	for (; i >= 8; i -= 8) {
		MULADDC_INIT
		MULADDC_HUIT
		MULADDC_STOP
	}

	for (; i > 0; i--) {
		MULADDC_INIT
		MULADDC_CORE
		MULADDC_STOP
	}
#else
	for (; i >= 16; i -= 16) {
		MULADDC_INIT
		MULADDC_CORE    MULADDC_CORE
		MULADDC_CORE    MULADDC_CORE
		MULADDC_CORE    MULADDC_CORE
		MULADDC_CORE    MULADDC_CORE

		MULADDC_CORE    MULADDC_CORE
		MULADDC_CORE    MULADDC_CORE
		MULADDC_CORE    MULADDC_CORE
		MULADDC_CORE    MULADDC_CORE
		MULADDC_STOP
	}

	for (; i >= 8; i -= 8) {
		MULADDC_INIT
		MULADDC_CORE    MULADDC_CORE
		MULADDC_CORE    MULADDC_CORE
		MULADDC_CORE    MULADDC_CORE
		MULADDC_CORE    MULADDC_CORE
		MULADDC_STOP
	}

	for (; i > 0; i--) {
		MULADDC_INIT
		MULADDC_CORE
		MULADDC_STOP
	}
#endif

	t++;
	do {
		*d += c;
		c = (*d < c);
		d++;
	} while (c != 0);
}

int
bn_mul_bn(bignum_t *x, bignum_t *y, bignum_t *z)
{
	int ret, i, j;
	bignum_t k, l;

	bzero(&k, sizeof(k));
	bzero(&l, sizeof(l));

	if (x == y) {
		BN_CHK(bn_copy(&k, y));
		y = &k;
	}

	if (x == z) {
		BN_CHK(bn_copy(&l, z));
		z = &l;
	}

	for (i = y->n-1; i >= 0; i--) {
		if (y->p[i] != 0) {
			break;
		}
	}

	for (j = z->n-1; j >= 0; j--) {
		if (z->p[j] != 0) {
			break;
		}
	}

	BN_CHK(bn_grow(x, i+j+2));
	BN_CHK(bn_lset(x, 0));
	for (i++; j >= 0; j--) {
		bn_mul_helper(i, y->p, x->p+j, z->p[j]);
	}
	x->s = y->s * z->s;

cleanup:
	bn_free(&k);
	bn_free(&l);

	return ret;
}

int
bn_mul_int(bignum_t *x, bignum_t *y, t_int z)
{
	bignum_t _z;
	t_int p[1];

	_z.s = 1;
	_z.n = 1;
	_z.p = p;
	p[0] = z;

	return bn_mul_bn(x, y, &_z);
}

int
bn_div_bn(bignum_t *q, bignum_t *r, bignum_t *y, bignum_t *z)
{
	int ret, i, n, t, k;
	bignum_t _x, _y, _z, t1, t2;

	if (bn_cmp_int(z, 0) == 0) {
		return BN_DIVISION_BY_ZERO;
	}

	bzero(&_x, sizeof(_x));
	bzero(&_y, sizeof(_y));
	bzero(&_z, sizeof(_z));
	bzero(&t1, sizeof(t1));
	bzero(&t2, sizeof(t2));
	if (bn_cmp_abs(y, z) < 0) {
		if (q != NULL) {
			BN_CHK(bn_lset(q, 0));
		}

		if (r != NULL) {
			BN_CHK(bn_copy(r, y));
		}

		return BN_SUCCESS;
	}

	BN_CHK(bn_copy(&_y, y));
	BN_CHK(bn_copy(&_z, z));
	_y.s = _z.s = 1;

	BN_CHK(bn_grow(&_x, y->n+2));
	BN_CHK(bn_lset(&_x, 0));
	BN_CHK(bn_grow(&t1, 2));
	BN_CHK(bn_grow(&t2, 3));

	k = bn_msb(&_z) % biL;
	if (k < (int)biL - 1) {
		k = biL - 1 - k;
		BN_CHK(bn_shift_L(&_y, k));
		BN_CHK(bn_shift_L(&_z, k));
	} else {
		k = 0;
	}

	n = _y.n - 1;
	t = _z.n - 1;
	bn_shift_L(&_z, biL * (n - t));

	while (bn_cmp_bn(&_y, &_z) >= 0) {
		_x.p[n-t]++;
		bn_sub_bn(&_y, &_y, &_z);
	}

	bn_shift_R(&_z, biL * (n - t));
	for (i = n; i > t; i--) {
		if (_y.p[i] >= _z.p[t]) {
			_x.p[i-t-1] = ~0;
		} else {
#ifdef HAVE_LONGLONG
			t_dbl r;

			r = (t_dbl)_y.p[i] << biL;
			r |= (t_dbl)_y.p[i-1];
			r /= _z.p[t];
			if (r > ((t_dbl)1 << biL) - 1) {
				r = ((t_dbl)1 << biL) - 1;
			}

			_x.p[i-t-1] = (t_int)r;
#else
			t_int q0, q1, r0, r1;
			t_int d0, d1, d, m;

			d = _z.p[t];
			d0 = (d<<biH) >> biH;
			d1 = (d >> biH);

			q1 = _y.p[i] / d1;
			r1 = _y.p[i] - d1 * q1;
			r1 <<= biH;
			r1 |= (_y.p[i-1]>>biH);

			m = q1 * d0;
			if (r1 < m) {
				q1--, r1 += d;
				while (r1 >= d && r1 < m) {
					q1--, r1 += d;
				}
			}
			r1 -= m;

			q0 = r1/d1;
			r0 = r1 - d1 * q0;
			r0 <<= biH;
			r0 |= (_y.p[i-1] << biH) >> biH;

			m = q0 * d0;
			if (r0 < m) {
				q0 --, r0 += d;
				while (r0 >= d && r0 < m) {
					q0--, r0 += d;
				}
			}
			r0 -= m;
			_x.p[i-t-1] = (q1 << biH) | q0;
#endif
		}

		_x.p[i - t - 1]++;
		do {
			_x.p[i-t-1]--;

			BN_CHK(bn_lset(&t1, 0));
			t1.p[0] = (t < 1) ? 0:_z.p[t-1];
			t1.p[1] = _z.p[t];
			BN_CHK(bn_mul_int(&t1, &t1, _x.p[i-t-1]));

			BN_CHK(bn_lset(&t2, 0));
			t2.p[0] = (i < 2)?0:_y.p[i-2];
			t2.p[1] = (i < 1)?0:_y.p[i-1];
			t2.p[2] = _y.p[i];
		} while (bn_cmp_bn(&t1, &t2) > 0);

		BN_CHK(bn_mul_int(&t1, &_z, _x.p[i-t-1]));
		BN_CHK(bn_shift_L(&t1, biL*(i-t-1)));
		BN_CHK(bn_sub_bn(&_y, &_y, &t1));

		if (bn_cmp_int(&_y, 0) < 0) {
			BN_CHK(bn_copy(&t1, &_z));
			BN_CHK(bn_shift_L(&t1, biL*(i-t-1)));
			BN_CHK(bn_sub_bn(&_y, &_y, &t1));
			_x.p[i-t-1]--;
		}
	}

	if (q != NULL) {
		bn_copy(q, &_x);
		q->s = y->s * z->s;
	}

	if (r != NULL) {
		bn_shift_R(&_y, k);
		bn_copy(r, &_y);

		r->s = y->s;
		if (bn_cmp_int(r, 0) == 0) {
			r->s = 1;
		}
	}

cleanup:
	bn_free(&_x);
	bn_free(&_y);
	bn_free(&_z);
	bn_free(&t1);
	bn_free(&t2);

	return ret;
}

int
bn_div_int(bignum_t *q, bignum_t *r, bignum_t *y, int z)
{
	bignum_t _z;
	t_int p[1];

	p[0] = (z < 0)?-z:z;
	_z.s = (z < 0)?-1:1;
	_z.n = 1;
	_z.p = p;

	return bn_div_bn(q, r, y, &_z);
}

int
bn_mod_bn(bignum_t *r, bignum_t *y, bignum_t *z)
{
	int ret;

	BN_CHK(bn_div_bn(NULL, r, y, z));

	while (bn_cmp_int(r, 0) < 0) {
		BN_CHK(bn_add_bn(r, r, z));
	}

	while (bn_cmp_bn(r, z) >= 0) {
		BN_CHK(bn_sub_bn(r, r, z));
	}

cleanup:
	return ret;
}

int 
bn_mod_int(t_int *r, bignum_t *y, int z)
{
	int i;
	t_int _x, _y, _z;

	if (z == 0) {
		return BN_DIVISION_BY_ZERO;
	}

	if (z < 0) {
		z = -z;
	}

	if (z == 1) {
		*r = 0;
		return BN_SUCCESS;
	}

	if (z == 2) {
		*r = y->p[0] & 1;
		return BN_SUCCESS;
	}

	for (i = y->n-1, _y = 0; i >= 0; i--) {
		_x = y->p[i];
		_y = (_y <<biH) | (_x >> biH);
		_z = _y / z;
		_y -= _z * z;

		_x <<= biH;
		_y = (_y << biH) | (_x>>biH);
		_z = _y / z;
		_y -= _z * z;
	}

	*r = _y;

	return BN_SUCCESS;
}

static void
bn_montg_init(t_int *m, bignum_t *N)
{
	t_int x, m0 = N->p[0];

	x = m0;
	x += ((m0 + 2) & 4) << 1;
	x *= (2 - (m0 * x));

	if (biL >= 16) {
		x *= (2 - (m0 * x));
	}

	if (biL >= 32) {
		x *= (2 - (m0 * x));
	}

	if (biL >= 64) {
		x *= (2 - (m0 * x));
	}

	*m = ~x + 1;
}

static void
bn_montmul(bignum_t *x, bignum_t *y, bignum_t *z, t_int mm, bignum_t *t)
{
	int i, n, m;
	t_int u0, u1, *d;

	bzero(t->p, ciL * t->n);

	d = t->p;
	n = z->n;
	m = (y->n < n)?y->n:n;

	for (i = 0; i < n; i++) {
		u0 = x->p[i];
		u1 = (d[0] + u0 * y->p[0]) * mm;

		bn_mul_helper(m, y->p, d, u0);
		bn_mul_helper(n, z->p, d, u1);

		*d++ = u0;
		d[n+1] = 0;
	}

	bcopy(d, x->p, ciL *(n+1));
	if (bn_cmp_abs(x, z) >= 0) {
		bn_sub_helper(n, z->p, x->p);
	} else {
		bn_sub_helper(n, x->p, t->p);
	}
}

static void
bn_montred(bignum_t *x, bignum_t *y, t_int mm, bignum_t *t)
{
	t_int z = 1;
	bignum_t u;

	u.n = u.s = z;
	u.p = &z;

	bn_montmul(x, &u, y, mm, t);
}

int
bn_exp_mod(bignum_t *x, bignum_t *y, bignum_t *e, bignum_t *n, bignum_t *_rr)
{
	int ret, i, j, wsize, wbits;
	int bufsize, nblimbs, nbits;
	t_int ei, mm, state;
	bignum_t rr, t, w[64];

	if (bn_cmp_int(n, 0) < 0 || (n->p[0] & 1) == 0) {
		return BN_INVALID_PARAM;
	}

	bn_montg_init(&mm, n);
	bzero(&rr, sizeof(rr));
	bzero(&t, sizeof(t));
	bzero(w, sizeof(w));

	i = bn_msb(e);
	wsize = (i > 671)?6:(i>239)?5:(i>79)?4:(i>23)?3:1;

	j = n->n + 1;
	BN_CHK(bn_grow(x, j));
	BN_CHK(bn_grow(&w[1], j));
	BN_CHK(bn_grow(&t, j*2));

	if (_rr == NULL || _rr->p == NULL) {
		BN_CHK(bn_lset(&rr, 1));
		BN_CHK(bn_shift_L(&rr, n->n*2*biL));
		BN_CHK(bn_mod_bn(&rr, &rr, n));

		if (_rr != NULL) {
			bcopy(&rr, _rr, sizeof(rr));
		}
	} else {
		bcopy(_rr, &rr, sizeof(rr));
	}

	if (bn_cmp_bn(y, n) >= 0) {
		bn_mod_bn(&w[1], y, n);
	} else {
		bn_copy(&w[1], y);
	}
	bn_montmul(&w[1], &rr, n, mm, &t);

	BN_CHK(bn_copy(x, &rr));
	bn_montred(x, n, mm, &t);

	if (wsize > 1) {
		j = 1 << (wsize - 1);

		BN_CHK(bn_grow(&w[j], n->n+1));
		BN_CHK(bn_copy(&w[j], &w[1]));
		for (i =0; i < wsize-1; i++) {
			bn_montmul(&w[j], &w[j], n, mm, &t);
		}

		for (i = j+1; i < (1<<wsize); i++) {
			BN_CHK(bn_grow(&w[i], n->n+1));
			BN_CHK(bn_copy(&w[i], &w[i-1]));

			bn_montmul(&w[i], &w[1], n, mm, &t);
		}
	}

	nblimbs = e->n;
	bufsize = 0;
	nbits = 0;
	wbits = 0;
	state = 0;

	while (1) {
		if (bufsize == 0) {
			if (nblimbs-- == 0) {
				break;
			}
			bufsize = sizeof(t_int) << 3;
		}

		bufsize--;
		ei = (e->p[nblimbs] >> bufsize) & 1;
		if (ei == 0 && state == 0) {
			continue;
		}

		if (ei == 0 && state == 1) {
			bn_montmul(x, x, n, mm, &t);
			continue;
		}

		state = 2;
		nbits++;
		wbits |= (ei << (wsize-nbits));

		if (nbits == wsize) {
			for (i = 0; i < wsize; i++) {
				bn_montmul(x, x, n, mm, &t);
			}

			bn_montmul(x, &w[wbits], n, mm, &t);

			state--;
			nbits = 0;
			wbits = 0;
		}
	}

	for (i = 0; i < nbits; i++) {
		bn_montmul(x, x, n, mm, &t);
		wbits <<= 1;

		if ((wbits & (1 << wsize)) != 0) {
			bn_montmul(x, &w[1], n, mm, &t);
		}
	}

	bn_montred(x, n, mm, &t);

cleanup:
	for (i = (1<<(wsize-1)); i < (1<<wsize); i++) {
		bn_free(&w[i]);
	}

	bn_free(&w[1]);
	bn_free(&t);
	if (_rr == NULL) {
		bn_free(&rr);
	}

	return ret;
}

int
bn_gcd(bignum_t *g, bignum_t *y, bignum_t *z)
{
	int ret, count;
	bignum_t _g, _y, _z;

	bzero(&_g, sizeof(_g));
	bzero(&_y, sizeof(_y));
	bzero(&_z, sizeof(_z));

	BN_CHK(bn_lset(&_g, 1));
	BN_CHK(bn_copy(&_y, y));
	BN_CHK(bn_copy(&_z, z));

	_y.s = _z.s = 1;
	count = (bn_lsb(&_y) < bn_lsb(&_z)) ? bn_lsb(&_y):bn_lsb(&_z);

	BN_CHK(bn_shift_L(&_g, count));
	BN_CHK(bn_shift_R(&_y, count));
	BN_CHK(bn_shift_R(&_z, count));

	while (bn_cmp_int(&_y, 0) != 0) {
		while ((_y.p[0] & 1) == 0) {
			BN_CHK(bn_shift_R(&_y, 1));
		}

		while ((_z.p[0] & 1) == 0) {
			BN_CHK(bn_shift_R(&_z, 1));
		}

		if (bn_cmp_bn(&_y, &_z) >= 0) {
			BN_CHK(bn_sub_abs(&_y, &_y, &_z));
			BN_CHK(bn_shift_R(&_y, 1));
		} else {
			BN_CHK(bn_sub_abs(&_z, &_z, &_y));
			BN_CHK(bn_shift_R(&_z, 1));
		}
	}

	BN_CHK(bn_mul_bn(g, &_g, &_z));

cleanup:
	bn_free(&_z);
	bn_free(&_y);
	bn_free(&_g);

	return ret;
}

int
bn_inv_mod(bignum_t *x, bignum_t *y, bignum_t *z)
{
	int ret;
	bignum_t g, _y, _u, _u1, _u2, _b, v, v1, v2;

	if (bn_cmp_int(z, 0) <= 0) {
		return BN_INVALID_PARAM;
	}

	bzero(&g, sizeof(g));
	bzero(&_y, sizeof(_y));
	bzero(&_u, sizeof(_u));
	bzero(&_u1, sizeof(_u1));
	bzero(&_u2, sizeof(_u2));
	bzero(&_b, sizeof(_b));
	bzero(&v, sizeof(v));
	bzero(&v1, sizeof(v1));
	bzero(&v2, sizeof(v2));

	BN_CHK(bn_gcd(&g, y, z));
	if (bn_cmp_int(&g, 1) != 0) {
		ret = BN_NOT_ACCEPTABLE;
		goto cleanup;
	}

	BN_CHK(bn_mod_bn(&_y, y, z));
	BN_CHK(bn_copy(&_u, &_y));
	BN_CHK(bn_copy(&_b, z));
	BN_CHK(bn_copy(&v, z));

	BN_CHK(bn_lset(&_u1, 1));
	BN_CHK(bn_lset(&_u2, 0));
	BN_CHK(bn_lset(&v1, 0));
	BN_CHK(bn_lset(&v2, 1));

	do {
		while ((_u.p[0] & 1) == 0) {
			BN_CHK(bn_shift_R(&_u, 1));

			if ((_u1.p[0] & 1) != 0 || (_u2.p[0] & 1) != 0) {
				BN_CHK(bn_add_bn(&_u1, &_u1, &_b));
				BN_CHK(bn_sub_bn(&_u2, &_u2, &_y));
			}

			BN_CHK(bn_shift_R(&_u1, 1));
			BN_CHK(bn_shift_R(&_u2, 1));
		}

		while ((v.p[0] & 1) == 0) {
			BN_CHK(bn_shift_R(&v, 1));

			if ((v1.p[0] & 1) != 0 || (v2.p[0] & 1) != 0) {
				BN_CHK(bn_add_bn(&v1, &v1, &_b));
				BN_CHK(bn_sub_bn(&v2, &v2, &_y));
			}

			BN_CHK(bn_shift_R(&v1, 1));
			BN_CHK(bn_shift_R(&v2, 1));
		}

		if (bn_cmp_bn(&_u, &v) >= 0) {
			BN_CHK(bn_sub_bn(&_u, &_u, &v));
			BN_CHK(bn_sub_bn(&_u1, &_u1, &v1));
			BN_CHK(bn_sub_bn(&_u2, &_u2, &v2));
		} else {
			BN_CHK(bn_sub_bn(&v, &v, &_u));
			BN_CHK(bn_sub_bn(&v1, &v1, &_u1));
			BN_CHK(bn_sub_bn(&v2, &v2, &_u2));
		}
	} while (bn_cmp_int(&_u, 0) != 0);

	while (bn_cmp_int(&v1, 0) < 0) {
		BN_CHK(bn_add_bn(&v1, &v1, z));
	}

	while (bn_cmp_bn(&v1, z) >= 0) {
		BN_CHK(bn_sub_bn(&v1, &v1, z));
	}

	BN_CHK(bn_copy(x, &v1));

cleanup:
	bn_free(&v);
	bn_free(&v1);
	bn_free(&v2);
	bn_free(&_b);
	bn_free(&g);
	bn_free(&_u2);
	bn_free(&_u1);
	bn_free(&_u);
	bn_free(&_y);

	return ret;
}

static const int small_prime[] = {
       3,  113,  271,  443,  619,  821,  1013,  1213,
       5,  127,  277,  449,  631,  823,  1019,  1217,
       7,  131,  281,  457,  641,  827,  1021,  1223,
      11,  137,  283,  461,  643,  829,  1031,  1229,
      13,  139,  293,  463,  647,  839,  1033,  1231,
      17,  149,  307,  467,  653,  853,  1039,  1237,
      19,  151,  311,  479,  659,  857,  1049,  1249,
      23,  157,  313,  487,  661,  859,  1051,  1259,
      29,  163,  317,  491,  673,  863,  1061,  1277,
      31,  167,  331,  499,  677,  877,  1063,  1279,
      37,  173,  337,  503,  683,  881,  1069,  1283,
      41,  179,  347,  509,  691,  883,  1087,  1289,
      43,  181,  349,  521,  701,  887,  1091,  1291,
      47,  191,  353,  523,  709,  907,  1093,  1297,
      53,  193,  359,  541,  719,  911,  1097,  1301,
      59,  197,  367,  547,  727,  919,  1103,  1303,
      61,  199,  373,  557,  733,  929,  1109,  1307,
      67,  211,  379,  563,  739,  937,  1117,  1319,
      71,  223,  383,  569,  743,  941,  1123,  1321,
      73,  227,  389,  571,  751,  947,  1129,  1327,
      79,  229,  397,  577,  757,  953,  1151,  1361,
      83,  233,  401,  587,  761,  967,  1153,  1367,
      89,  239,  409,  593,  769,  971,  1163,  1373,
      97,  241,  419,  599,  773,  977,  1171,  1381,
     101,  251,  421,  601,  787,  983,  1181,  1399,
     103,  257,  431,  607,  797,  991,  1187,  1409,
     107,  263,  433,  613,  809,  997,  1193,  1423,
     109,  269,  439,  617,  811, 1009,  1201,  -111
};

static unsigned long randseed = 1;

static unsigned long
rand(void *dumy)
{
	register long x, hi, lo, t;

	x = randseed;
	hi = x / 127773;
	lo = x % 127773;
	t = 16807 * lo - 2836 * hi;
	if (t <= 0) {
		t += 0x7fffffff;
	}

	randseed = t;
	return t;
}

int
bn_is_prime(bignum_t *x)
{
	int ret, i, j, s, xs;
	bignum_t w, r, t, a, rr;

	if (bn_cmp_int(x, 0) == 0) {
		return BN_SUCCESS;
	}

	bzero(&w, sizeof(w));
	bzero(&r, sizeof(r));
	bzero(&t, sizeof(t));
	bzero(&a, sizeof(a));
	bzero(&rr, sizeof(rr));
	xs = x->s;
	x->s = 1;

	if ((x->p[0] & 1) == 0) {
		return BN_NOT_ACCEPTABLE;
	}

	for (i = 0; small_prime[i] > 0; i++) {
		t_int r;

		if (bn_cmp_int(x, small_prime[i]) <= 0) {
			return 0;
		}

		BN_CHK(bn_mod_int(&r, x, small_prime[i]));
		if (r == 0) {
			return BN_NOT_ACCEPTABLE;
		}
	}

	BN_CHK(bn_sub_int(&w, x, 1));
	BN_CHK(bn_copy(&r, &w));
	s = bn_lsb(&w);
	BN_CHK(bn_shift_R(&r, s));

	for (i = 0; i < 8; i++) {
		BN_CHK(bn_grow(&a, x->n));

		for (j = 0; j < a.n; j++) {
			a.p[j] = (t_int)rand(NULL) * rand(NULL);
		}

		BN_CHK(bn_shift_R(&a, bn_msb(&a)-bn_msb(&w)+1));
		a.p[0] |= 3;

		BN_CHK(bn_exp_mod(&a, &a, &r, x, &rr));
		if (bn_cmp_bn(&a, &w) == 0 ||
		    bn_cmp_int(&a, 1) == 0) {
			continue;
		}

		j = 1;
		while (j < 2 && bn_cmp_bn(&a, &w) != 0) {
			BN_CHK(bn_mul_bn(&t, &a, &a));
			BN_CHK(bn_mod_bn(&a, &t, x));

			if (bn_cmp_int(&a, 1) == 0) {
				break;
			}

			j++;
		}

		if (bn_cmp_bn(&a, &w) != 0 || j < s) {
			ret = BN_NOT_ACCEPTABLE;
			break;
		}
	}

cleanup:
	x->s = xs;
	bn_free(&a);
	bn_free(&t);
	bn_free(&r);
	bn_free(&w);

	return ret;
}

int
bn_gen_prime(bignum_t *x, int nbits, int dh_flag,
             unsigned long (*rng_f)(void *), void *rng_d)
{
	int ret, k, n;
	unsigned char *p;
	bignum_t y;

	if (nbits < 3) {
		return BN_INVALID_PARAM;
	}

	if (rng_f == NULL) {
		rng_f = rand;
	}

	bzero(&y, sizeof(y));
	n = BITS_TO_LIMBS(nbits);
	BN_CHK(bn_grow(x, n));
	BN_CHK(bn_lset(x, 0));

	p = (unsigned char *)x->p;
	for (k = 0; k < ciL * x->n; k++) {
		*p++ = rng_f(rng_d);
	}

	k = bn_msb(x);
	if (k < nbits) {
		BN_CHK(bn_shift_L(x, nbits - k));
	}

	if (k < nbits) {
		BN_CHK(bn_shift_R(x, k-nbits));
	}

	x->p[0] |= 3;
	if (dh_flag == 0) {
		while ((ret = bn_is_prime(x)) != 0) {
			if (ret != BN_NOT_ACCEPTABLE) {
				goto cleanup;
			}

			BN_CHK(bn_add_int(x, x, 2));
		}
	} else {
		BN_CHK(bn_sub_int(&y, x, 1));
		BN_CHK(bn_shift_R(&y, 1));

		while (1) {
			if ((ret = bn_is_prime(x)) == 0) {
				if ((ret = bn_is_prime(&y)) == 0) {
					break;
				}

				if (ret != BN_NOT_ACCEPTABLE) {
					goto cleanup;
				}
			}

			if (ret != BN_NOT_ACCEPTABLE) {
				goto cleanup;
			}

			BN_CHK(bn_add_int(&y, x, 1));
			BN_CHK(bn_add_int(x, x, 2));
			BN_CHK(bn_shift_R(&y, 1));
		}
	}

cleanup:
	bn_free(&y);

	return ret;
}

#ifdef _RUN_TEST
#include <time.h>

static int
strim_head(char *str, char c)
{
	int offset = 0;
	int len;

	if (str == NULL) {
		return 0;
	}

	len = strlen(str);
	do {
		if (str[offset] != c) {
			break;
		}
	} while (++offset < len);

	return offset;
}

int
bn_test(int verbose)
{
	int ret;
	bignum_t A, E, N, X, Y, U, V;
	char out_str[1024];
	int len, offset = 0;
	time_t start, end;
	int i;

	char A_str[] = "EFE021C2645FD1DC586E69184AF4A31E" \
	               "D5F53E93B5F123FA41680867BA110131" \
	               "944FE7952E2517337780CB0DB80E61AA" \
	               "E7C8DDC6C5C6AADEB34EB38A2F40D5E6";
	char E_str[] = "B2E7EFD37075B9F03FF989C7C5051C20" \
	               "34D2A323810251127E7BF8625A4F49A5" \
	               "F3E27F4DA8BD59C47D6DAABA4C8127BD" \
	               "5B5C25763222FEFCCFC38B832366C29E";

	char N_str[] = "0066A198186C18C10B2F5ED9B522752A" \
	               "9830B69916E535C8F047518A889A43A5" \
	               "94B6BED27A168D31D4A52F88925AA8F5";

	char U_str[] = "602AB7ECA597A3D6B56FF9829A5E8B85" \
	               "9E857EA95A03512E2BAE7391688D264A" \
	               "A5663B0341DB9CCFD2C4C5F421FEC814" \
	               "8001B72E848A38CAE1C65F78E56ABDEF" \
	               "E12D3C039B8A02D6BE593F0BBBDA56F1" \
	               "ECF677152EF804370C1A305CAF3B5BF1" \
	               "30879B56C61DE584A0F53A2447A51E";

	char U_str1[] = "256567336059E52CAE22925474705F39A94";

	char U_str2[] = "36E139AEA55215609D2816998ED020BB" \
	                "BD96C37890F65171D948E9BC7CBAA4D9" \
	                "325D24D6A3C12710F10A09FA08AB87";

	char U_str3[] = "003A0AAEDD7E784FC07D8F9EC6E3BFD5" \
	                "C3DBA76456363A10869622EAC2DD84EC" \
	                "C5B8A74DAC4D09E03B5E0BE779F2DF61";

	char V_str[] = "6613F26162223DF488E9CD48CC132C7A" \
	               "0AC93C701B001B092E4E5B9F73BCD27B" \
	               "9EE50D0657C77F374E903CDFA4C642";

	bzero(&A, sizeof(A));
	bzero(&E, sizeof(E));
	bzero(&N, sizeof(N));
	bzero(&X, sizeof(X));
	bzero(&Y, sizeof(Y));
	bzero(&U, sizeof(U));
	bzero(&V, sizeof(V));

	start = time(NULL);
	for (i = 0; i < 1000000; i++) {
		BN_CHK(bn_read_string(&A, 16, A_str, strlen(A_str)));
		BN_CHK(bn_read_string(&E, 16, E_str, strlen(E_str)));
		BN_CHK(bn_read_string(&N, 16, N_str, strlen(N_str)));
		BN_CHK(bn_mul_bn(&X, &A, &N));
	}
	end = time(NULL);

	printf("1000000 times bignum mul spends %ds\n", end - start);
	len = sizeof(out_str) - 1;
	bzero(out_str, sizeof(out_str));
	BN_CHK(bn_write_string(&X, 16, out_str, &len));
	BN_CHK(bn_read_string(&U, 16, U_str, strlen(U_str)));

	if (verbose != 0) {
		printf("  bignum test #1 (mul_bn): ");
	}

	if (bn_cmp_bn(&X, &U) != 0) {
		if (verbose != 0) {
			printf("failed\n");
		}

		return 1;
	}

	if (verbose != 0)
		printf("passed\n");

	offset = strim_head(out_str, '0');
	printf("  bignum test #1 (write_string): ");
	if (strcasecmp(out_str+offset, U_str) != 0) {
		printf("failed\n");
	} else {
		printf("passed\n");
	}

	BN_CHK(bn_div_bn(&X, &Y, &A, &N));

	BN_CHK(bn_read_string(&U, 16, U_str1, strlen(U_str1)));
	BN_CHK(bn_read_string(&V, 16, V_str, strlen(V_str)));

	if (verbose != 0) {
		printf("  bignum test #2 (div_bn): ");
	}

	if (bn_cmp_bn(&X, &U) != 0 ||
	    bn_cmp_bn(&Y, &V) != 0) {
		if (verbose != 0) {
			printf("failed\n");
		}

		return 1;
	}

	if (verbose != 0) {
		printf("passed\n");
	}

	len = sizeof(out_str) - 1;
	bzero(out_str, sizeof(out_str));
	BN_CHK(bn_write_string(&X, 16, out_str, &len));

	offset = strim_head(out_str, '0');

	printf("  bignum test #2 (write_string): ");
	if (strcasecmp(out_str+offset, U_str1) != 0) {
		printf("failed\n");
	} else {
		printf("passed\n");
	}

	BN_CHK(bn_exp_mod(&X, &A, &E, &N, NULL));
	BN_CHK(bn_read_string(&U, 16, U_str2, strlen(U_str2)));

	if (verbose != 0) {
		printf("  bignum test #3 (exp_mod): ");
	}

	if (bn_cmp_bn(&X, &U) != 0) {
		if (verbose != 0) {
			printf("failed\n");
		}

		return 1;
	}

	if (verbose != 0) {
		printf("passed\n");
	}

	BN_CHK(bn_inv_mod(&X, &A, &N));
	BN_CHK(bn_read_string(&U, 16, U_str3, strlen(U_str3)));

	if (verbose != 0) {
		printf("  bignum test #4 (inv_mod): ");
	}

	if (bn_cmp_bn(&X, &U) != 0) {
		if (verbose != 0) {
			printf("failed\n");
		}

		return 1;
	}

	if (verbose != 0) {
		printf("passed\n");
	}

 cleanup:

	if (ret != 0 && verbose != 0) {
		printf("Unexpected error, return code = %08X\n", ret);
	}

	bn_free(&V);
	bn_free(&U);
	bn_free(&Y);
	bn_free(&X);
	bn_free(&N);
	bn_free(&E);
	bn_free(&A);
	if (verbose != 0) {
		printf("\n");
	}

	return ret;
}

int
main(int argc, char *argv[])
{
	bn_test(1);

	return 0;
}
#endif
