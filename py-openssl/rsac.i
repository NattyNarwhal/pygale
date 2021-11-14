%module rsac

%pragma make_default

%{
#include "openssl/ssl.h"
%}

typedef struct
{
	/* The first parameter is used to pickup errors where
	 * this is passed instead of aEVP_PKEY, it is set to 0 */
        int pad;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *dmp1;
	BIGNUM *dmq1;
	BIGNUM *iqmp;
	/* be careful using this if the RSA structure is shared */
	int flags;
} RSA;

RSA* RSA_new();
void RSA_free(RSA* r);
