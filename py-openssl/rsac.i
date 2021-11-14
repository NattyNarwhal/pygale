%module rsac

%pragma make_default

%{
#include "openssl/ssl.h"

#include <stdio.h>
%}

typedef struct RSA;

int RSA_flags(const RSA *rsa);
void RSA_set_flags(RSA *r, int flags);
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
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
