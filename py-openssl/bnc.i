%module bnc

%pragma make_default

%{
#include "openssl/bn.h"
%}


typedef struct BIGNUM;

%typemap(in) const unsigned char * 
{
	if (PyString_Check($input)) 
	{
		$1 = PyString_AsString($input);
	} 
	else 
	{
		PyErr_SetString(PyExc_TypeError, "expected a string");
		return NULL;
	}
}

%typemap(in) BIGNUM *ret
{
	char *return_bignum_name;

	if ($input == Py_None)
	{
		$1 = NULL;
	}
	else
	{
		return_bignum_name = PyString_AsString($input);
		if (SWIG_ConvertPtr(return_bignum_name,
                    (void **) &$1, SWIGTYPE_p_BIGNUM, 0)) {
			PyErr_SetString(PyExc_TypeError,"Type error in argument 3 of BN_bin2bn. Expected _BIGNUM_p.");
			return NULL;
		}
	}
}

BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
BIGNUM *BN_new(void);
char   *BN_bn2hex(const BIGNUM *a);
void	BN_free(BIGNUM* bn);

