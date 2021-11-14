%module evpc

%pragma make_default

%{
#include "openssl/ssl.h"
%}

typedef struct EVP_MD_CTX;

typedef struct EVP_PKEY;

%{
void
EVP_MD_CTX_free(EVP_MD_CTX* ctx)
{
	if (ctx != NULL)
	{
		free(ctx);
	}
}

PyObject*
python_EVP_SignFinal(EVP_MD_CTX* ctx, EVP_PKEY* pkey)
{
	PyObject* python_string;
	PyObject* return_obj;
	char* buf;
	int buf_len;
	int result;

	buf_len = EVP_PKEY_size(pkey);
	python_string = PyString_FromStringAndSize(NULL, buf_len);
	if (python_string == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for SignFinal buffer.");
		return NULL;
	}
	buf = PyString_AsString(python_string);
	result = EVP_SignFinal(ctx, buf, &buf_len, pkey);
	if (result == 0)
	{
		Py_DECREF(python_string);
		python_string = Py_None;
		Py_INCREF(python_string);
	}
	else
	{
		_PyString_Resize(&python_string, buf_len);
	}

	return_obj = Py_BuildValue("O", python_string);
	Py_DECREF(python_string);

	return return_obj;
}

void
EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx)
{
	if (ctx != NULL)
	{
		free(ctx);
	}
}

PyObject*
python_EVP_SealInit(EVP_CIPHER_CTX* ctx, EVP_CIPHER* type, PyObject* public_keys)
{
	int i;
	int num_public_keys = 0;
	EVP_PKEY** evp_public_keys = NULL;
	PyObject* pkey_object = NULL;
	PyObject* pkey_object_name = NULL;
	EVP_PKEY* pkey = NULL;
	int encrypted_key_buf_len = 0;
	char** buffers = NULL;
	int* buffer_lengths = NULL;
	PyObject** python_strings = NULL;
	PyObject* python_iv_string = NULL;
	char* iv_buf = NULL;
	PyObject* return_list;
	PyObject* return_object = NULL;
	int result;

	num_public_keys = PyList_Size(public_keys);
	evp_public_keys = (EVP_PKEY**) malloc(sizeof(EVP_PKEY*) * num_public_keys);
	if (evp_public_keys == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for encrypted key buffers.");
		return NULL;
	}
	buffers = (char **) malloc(sizeof(char*) * num_public_keys);
	if (buffers == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for encrypted key buffers.");
		goto error_cleanup;
	}
	python_strings = (PyObject **) malloc(sizeof(PyObject*) * num_public_keys);
	if (python_strings == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for encrypted key buffers.");
		goto error_cleanup;
	}
	buffer_lengths = (int *) malloc(sizeof(int) * num_public_keys);
	if (buffer_lengths == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for encrypted key buffers.");
		goto error_cleanup;
	}

	for (i = 0; i < num_public_keys; ++i)
	{
		python_strings[i] = NULL;
		pkey_object = PyList_GetItem(public_keys, i);
		pkey_object_name = PyObject_GetAttrString(pkey_object, "ptr");
		if
                (SWIG_ConvertPtr(PyString_AsString(pkey_object_name),
                (void**) &pkey, SWIGTYPE_p_EVP_PKEY, 0))
		{
			PyErr_SetString(PyExc_TypeError, "Type error in list of public keys. Each item should be a evp.PKEY instance.");
			goto error_cleanup;
		}
		evp_public_keys[i] = pkey;
		encrypted_key_buf_len = EVP_PKEY_size(pkey);
		python_strings[i] = PyString_FromStringAndSize(NULL, encrypted_key_buf_len);
		if (python_strings[i] == NULL)
		{
			PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for encrypted key buffers.");
			goto error_cleanup;
		}
		buffers[i] = PyString_AsString(python_strings[i]);
	}
	python_iv_string = PyString_FromStringAndSize(NULL, EVP_MAX_IV_LENGTH);
	if (python_iv_string == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for encrypted key buffers.");
		goto error_cleanup;
	}
	iv_buf = PyString_AsString(python_iv_string);
	result = EVP_SealInit(ctx, type, (unsigned char**) buffers, buffer_lengths, iv_buf,
			      evp_public_keys, num_public_keys);
	if (result != 0)
	{
		return_list = PyList_New(num_public_keys);
		for (i = 0; i < num_public_keys; ++i)
		{
			_PyString_Resize(&python_strings[i], buffer_lengths[i]);
			PyList_SetItem(return_list, i, python_strings[i]);
		}
		return_object = Py_BuildValue("OO", python_iv_string, return_list);
		Py_DECREF(return_list);
		Py_DECREF(python_iv_string);
		goto cleanup;
	}

error_cleanup:
	for (i = 0; i < num_public_keys; ++i)
	{
		if (python_strings[i] != NULL)
		{
			Py_DECREF(python_strings[i]);
		}
	}
	Py_DECREF(python_iv_string);

cleanup:
	free(evp_public_keys);
	free(buffers);
	free(python_strings);
	free(buffer_lengths);

	return return_object;
}

PyObject*
python_EVP_SealUpdate(EVP_CIPHER_CTX* ctx, PyObject* unencrypted_data)
{
	int encrypted_data_len;
	PyObject* encrypted_python_string;
	PyObject* return_obj;
	char* encrypted_data_buf;
	char* unencrypted_data_buf;
	int unencrypted_data_len;

	unencrypted_data_buf = PyString_AsString(unencrypted_data);
	unencrypted_data_len = PyString_Size(unencrypted_data);

	encrypted_data_len = PyString_Size(unencrypted_data) + EVP_CIPHER_CTX_block_size(ctx) - 1;
	encrypted_python_string = PyString_FromStringAndSize(NULL, encrypted_data_len);
	if (encrypted_python_string == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for encrypted key buffers.");
		return NULL;
	}
	encrypted_data_buf = PyString_AsString(encrypted_python_string);

	/* Version 0.9.5a of OpenSSL does not return a value from SealUpdate,
	 * whereas 0.9.6 returns an int.  Ignore the return value and always
	 * assume success---this could expose a bug.
	 */
	EVP_SealUpdate(ctx, encrypted_data_buf, &encrypted_data_len, unencrypted_data_buf, unencrypted_data_len);
	_PyString_Resize(&encrypted_python_string, encrypted_data_len);
	
	return_obj = Py_BuildValue("O", encrypted_python_string);
	Py_DECREF(encrypted_python_string);
	
	return return_obj;
}

PyObject*
python_EVP_SealFinal(EVP_CIPHER_CTX* ctx)
{
	int encrypted_data_len;
	PyObject* encrypted_python_string;
	PyObject* return_obj;
	char* encrypted_data_buf;

	encrypted_data_len = EVP_CIPHER_CTX_block_size(ctx) - 1;
	encrypted_python_string = PyString_FromStringAndSize(NULL, encrypted_data_len);
	if (encrypted_python_string == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for encrypted key buffers.");
		return NULL;
	}
	encrypted_data_buf = PyString_AsString(encrypted_python_string);

	EVP_SealFinal(ctx, encrypted_data_buf, &encrypted_data_len);
	_PyString_Resize(&encrypted_python_string, encrypted_data_len);

	return_obj = Py_BuildValue("O", encrypted_python_string);
	Py_DECREF(encrypted_python_string);
	
	return return_obj;
}

PyObject*
python_EVP_OpenUpdate(EVP_CIPHER_CTX* ctx, PyObject* encrypted_data)
{
	PyObject* unencrypted_python_string;
	PyObject* return_obj;
	char* unencrypted_data_buf;
	int unencrypted_data_len;
	char* encrypted_data_buf;
	int encrypted_data_len;

	encrypted_data_buf = PyString_AsString(encrypted_data);
	encrypted_data_len = PyString_Size(encrypted_data);

	unencrypted_data_len = PyString_Size(encrypted_data) + EVP_CIPHER_CTX_block_size(ctx) - 1;
	unencrypted_python_string = PyString_FromStringAndSize(NULL, unencrypted_data_len);
	if (unencrypted_python_string == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for unencrypted buffers.");
		return NULL;
	}
	unencrypted_data_buf = PyString_AsString(unencrypted_python_string);

	EVP_OpenUpdate(ctx, unencrypted_data_buf, &unencrypted_data_len, encrypted_data_buf, encrypted_data_len);
	_PyString_Resize(&unencrypted_python_string, unencrypted_data_len);
	
	return_obj = Py_BuildValue("O", unencrypted_python_string);
	Py_DECREF(unencrypted_python_string);
	
	return return_obj;
}

PyObject*
python_EVP_OpenFinal(EVP_CIPHER_CTX* ctx)
{
	PyObject* unencrypted_python_string;
	PyObject* return_obj;
	char* unencrypted_data_buf;
	int unencrypted_data_len;
	char* encrypted_data_buf;
	int encrypted_data_len;
	int result;

	unencrypted_data_len = EVP_CIPHER_CTX_block_size(ctx);
	unencrypted_python_string = PyString_FromStringAndSize(NULL, unencrypted_data_len);
	if (unencrypted_python_string == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for unencrypted buffers.");
		return NULL;
	}
	unencrypted_data_buf = PyString_AsString(unencrypted_python_string);

	result = EVP_OpenFinal(ctx, unencrypted_data_buf, &unencrypted_data_len);
	if (result == 0)
	{
		Py_DECREF(unencrypted_python_string);
		unencrypted_python_string = Py_None;
		Py_INCREF(unencrypted_python_string);
	}
	else
	{
		_PyString_Resize(&unencrypted_python_string, unencrypted_data_len);
	}
	
	return_obj = Py_BuildValue("O", unencrypted_python_string);
	Py_DECREF(unencrypted_python_string);
	
	return return_obj;
}

%}

%typemap(out) PyObject*
{
	$result = $1;
}

%typemap(in) PyObject*
{
	$1 = $input;
}

%typemap(in) unsigned char*
{
	$1 = PyString_AsString($input);
}

/*  */
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);
RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey);

int		EVP_PKEY_assign_RSA(EVP_PKEY *pkey, RSA *rsa_key);
EVP_PKEY*	EVP_PKEY_new(void);
void		EVP_PKEY_free(EVP_PKEY* pkey);
EVP_MD*		EVP_md5(void);
EVP_CIPHER*	EVP_des_ede3_cbc(void);
EVP_MD_CTX* 	EVP_MD_CTX_new(void);
void		EVP_MD_CTX_free(EVP_MD_CTX* ctx);
void		EVP_SignInit(EVP_MD_CTX *ctx, const EVP_MD *type);
void		EVP_SignUpdate(EVP_MD_CTX *ctx,unsigned char *d, unsigned int cnt);
int		EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s, EVP_PKEY *pkey);
PyObject*	python_EVP_SignFinal(EVP_MD_CTX* ctx, EVP_PKEY* pkey);
int		EVP_SealInit(EVP_CIPHER_CTX *ctx, EVP_CIPHER *type, unsigned char **ek, int *ekl, unsigned char *iv,EVP_PKEY **pubk, int npubk);
void		EVP_SealUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl);
void		EVP_SealFinal(EVP_CIPHER_CTX *ctx,unsigned char *out,int *outl);
EVP_CIPHER_CTX*	EVP_CIPHER_CTX_new(void);
void		EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx);
PyObject* 	python_EVP_SealInit(EVP_CIPHER_CTX* ctx, EVP_CIPHER* type, PyObject* public_keys);
PyObject*	python_EVP_SealUpdate(EVP_CIPHER_CTX* ctx, PyObject* unencrypted_data);
PyObject*	python_EVP_SealFinal(EVP_CIPHER_CTX* ctx);
int		EVP_OpenInit(EVP_CIPHER_CTX* ctx, EVP_CIPHER* type,unsigned char *ek, int ekl,unsigned char* iv,EVP_PKEY* priv);
void		EVP_OpenUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, unsigned char* in, int inl);
int		EVP_OpenFinal(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl); 
PyObject*	python_EVP_OpenUpdate(EVP_CIPHER_CTX* ctx, PyObject* encrypted_data);
PyObject*	python_EVP_OpenFinal(EVP_CIPHER_CTX* ctx);
void		EVP_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *type);
void		EVP_VerifyUpdate(EVP_MD_CTX *ctx,unsigned char *d, unsigned int cnt);
int		EVP_VerifyFinal(EVP_MD_CTX *ctx,unsigned char *sigbuf, unsigned int siglen,EVP_PKEY *pkey);
