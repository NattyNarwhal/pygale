%module rsac

%pragma make_default

%{
#include "openssl/ssl.h"

#include <stdio.h>
%}

typedef struct RSA;

int RSA_flags(const RSA *rsa);
void RSA_set_flags(RSA *r, int flags);

/* Wrappers for the fact these aren't transparent in OpenSSL */
%{
int py_RSA_set0_n(RSA *r, const BIGNUM *n)
{
	const BIGNUM *e, *d;
	e = RSA_get0_e(r);
	d = RSA_get0_d(r);
fprintf(stderr, "**set n** r=%p n=%p e=%p d=%p\n", r, n, e, d);
	return RSA_set0_key(r, (BIGNUM*)n, (BIGNUM*)e, (BIGNUM*)d);
}

int py_RSA_set0_e(RSA *r, const BIGNUM *e)
{
	const BIGNUM *n, *d;
	n = RSA_get0_n(r);
	d = RSA_get0_d(r);
fprintf(stderr, "**set e** r=%p n=%p e=%p d=%p\n", r, n, e, d);
	return RSA_set0_key(r, (BIGNUM*)n, (BIGNUM*)e, (BIGNUM*)d);
}

int py_RSA_set0_d(RSA *r, const BIGNUM *d)
{
	const BIGNUM *n, *e;
	n = RSA_get0_n(r);
	e = RSA_get0_e(r);
fprintf(stderr, "**set d** r=%p n=%p e=%p d=%p\n", r, n, e, d);
	return RSA_set0_key(r, (BIGNUM*)n, (BIGNUM*)e, (BIGNUM*)d);
}

int py_RSA_set0_p(RSA *r, const BIGNUM *p)
{
	const BIGNUM *q;
	q = RSA_get0_q(r);
fprintf(stderr, "**set p** r=%p p=%p q=%p\n", r, p, q);
	return RSA_set0_factors(r, (BIGNUM*)p, (BIGNUM*)q);
}

int py_RSA_set0_q(RSA *r, const BIGNUM *q)
{
	const BIGNUM *p;
	p = RSA_get0_p(r);
fprintf(stderr, "**set q** r=%p p=%p q=%p\n", r, p, q);
	return RSA_set0_factors(r, (BIGNUM*)p, (BIGNUM*)q);
}

int py_RSA_set0_dmp1(RSA *r, const BIGNUM *dmp1)
{
	const BIGNUM *dmq1, *iqmp;
	dmq1 = RSA_get0_dmq1(r);
	iqmp = RSA_get0_iqmp(r);
fprintf(stderr, "**set dmp1** r=%p dmp1=%p dmq1=%p iqmp=%p\n", r, dmp1, dmq1, iqmp);
	return RSA_set0_crt_params(r, (BIGNUM*)dmp1, (BIGNUM*)dmq1, (BIGNUM*)iqmp);
}

int py_RSA_set0_dmq1(RSA *r, const BIGNUM *dmq1)
{
	const BIGNUM *dmp1, *iqmp;
	dmp1 = RSA_get0_dmp1(r);
	iqmp = RSA_get0_iqmp(r);
fprintf(stderr, "**set dmq1** r=%p dmp1=%p dmq1=%p iqmp=%p\n", r, dmp1, dmq1, iqmp);
	return RSA_set0_crt_params(r, (BIGNUM*)dmp1, (BIGNUM*)dmq1, (BIGNUM*)iqmp);
}

int py_RSA_set0_iqmp(RSA *r, const BIGNUM *iqmp)
{
	const BIGNUM *dmp1, *dmq1;
	dmq1 = RSA_get0_dmq1(r);
	dmp1 = RSA_get0_dmp1(r);
fprintf(stderr, "**set iqmp** r=%p dmp1=%p dmq1=%p iqmp=%p\n", r, dmp1, dmq1, iqmp);
	return RSA_set0_crt_params(r, (BIGNUM*)dmp1, (BIGNUM*)dmq1, (BIGNUM*)iqmp);
}
%}

int py_RSA_set0_n(RSA *r, const BIGNUM *n);
int py_RSA_set0_e(RSA *r, const BIGNUM *e);
int py_RSA_set0_d(RSA *r, const BIGNUM *d);
int py_RSA_set0_p(RSA *r, const BIGNUM *p);
int py_RSA_set0_q(RSA *r, const BIGNUM *q);
int py_RSA_set0_dmp1(RSA *r, const BIGNUM *dmp1);
int py_RSA_set0_dmq1(RSA *r, const BIGNUM *dmq1);
int py_RSA_set0_iqmp(RSA *r, const BIGNUM *iqmp);

const BIGNUM *RSA_get0_n(const RSA *d);
const BIGNUM *RSA_get0_e(const RSA *d);
const BIGNUM *RSA_get0_d(const RSA *d);
const BIGNUM *RSA_get0_p(const RSA *d);
const BIGNUM *RSA_get0_q(const RSA *d);
const BIGNUM *RSA_get0_dmp1(const RSA *r);
const BIGNUM *RSA_get0_dmq1(const RSA *r);
const BIGNUM *RSA_get0_iqmp(const RSA *r);

RSA* RSA_new();
void RSA_free(RSA* r);
